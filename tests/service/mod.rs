/*
 * Service abstraction provides a way to automatically generate services that are attached to
 * TestNetworks for testing against. Each Service is composed of a DNS service attached to a
 * TestNetwork. The service can then be resolved against, for example. Several parameters for
 * managing the underlying TestNetwork, and the Service are available via the ServiceConfig struct.
 */

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Add,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use ipnetwork::IpNetwork;
use openssl::{
    pkey::{PKey, Private},
    stack::Stack,
    x509::X509,
};
use rand::prelude::{IteratorRandom, SliceRandom};
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::info;
use trust_dns_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    Name,
};

use zeronsd::{
    addresses::Calculator,
    authority::{find_members, RecordAuthority, ZTAuthority},
    server::Server,
    traits::{ToHostname, ToPointerSOA},
    utils::{authtoken_path, domain_or_default, get_listen_ips, parse_ip_from_cidr},
};

use self::{
    context::TestContext,
    network::TestNetwork,
    resolver::{Lookup, Resolver, Resolvers},
    utils::{format_hosts_file, HostsType},
};

pub mod context;
pub mod member;
pub mod network;
pub mod resolver;
pub mod to_ip;
pub mod utils;

pub struct ServiceConfig {
    hosts: HostsType,
    update_interval: Option<Duration>,
    ips: Option<Vec<&'static str>>,
    wildcard_everything: bool,
    network_filename: Option<&'static str>,
    tls: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            network_filename: None,
            hosts: HostsType::None,
            update_interval: None,
            ips: None,
            wildcard_everything: false,
            tls: false,
        }
    }
}

impl ServiceConfig {
    pub fn tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }

    pub fn network_filename(mut self, n: &'static str) -> Self {
        self.network_filename = Some(n);
        self
    }

    pub fn hosts(mut self, h: HostsType) -> Self {
        self.hosts = h;
        self
    }

    pub fn update_interval(mut self, u: Option<Duration>) -> Self {
        self.update_interval = u;
        self
    }

    pub fn ips(mut self, ips: Option<Vec<&'static str>>) -> Self {
        self.ips = ips;
        self
    }

    pub fn wildcard_everything(mut self, w: bool) -> Self {
        self.wildcard_everything = w;
        self
    }
}

#[derive(Clone)]
pub struct Service {
    tn: Arc<TestNetwork>,
    resolvers: Resolvers,
    update_interval: Option<Duration>,
    pub listen_ips: Vec<SocketAddr>,
    servers: Arc<Mutex<Vec<JoinHandle<Result<(), anyhow::Error>>>>>,
    authority_func: Arc<Mutex<JoinHandle<()>>>,
}

impl Drop for Service {
    fn drop(&mut self) {
        tokio::task::block_in_place(|| {
            self.servers
                .blocking_lock()
                .iter()
                .map(|x| x.abort())
                .count();
            self.authority_func.blocking_lock().abort();
        })
    }
}

impl Service {
    pub async fn new(sc: ServiceConfig) -> Self {
        let network_filename = sc.network_filename.unwrap_or("basic-ipv4");
        let tn = if let Some(ips) = sc.ips {
            TestNetwork::new_multi_ip(network_filename, &mut TestContext::default().await, ips)
                .await
                .unwrap()
        } else {
            TestNetwork::new(network_filename, &mut TestContext::default().await)
                .await
                .unwrap()
        };

        let (cert, private_key) = Self::load_certs(sc.tls).unwrap();

        let (listen_ips, servers, authority_func) = Self::create_listeners(
            &tn,
            sc.hosts,
            sc.update_interval,
            sc.wildcard_everything,
            cert.clone(),
            private_key,
        )
        .await;

        Self {
            resolvers: Self::create_resolvers(
                listen_ips.clone(),
                cert,
                tn.member()
                    .to_fqdn(domain_or_default(None).unwrap())
                    .unwrap(),
            ),
            tn: Arc::new(tn),
            listen_ips,
            update_interval: sc.update_interval,
            servers: Arc::new(Mutex::new(servers)),
            authority_func: Arc::new(Mutex::new(authority_func)),
        }
    }

    fn load_certs(tls: bool) -> Result<(Option<X509>, Option<PKey<Private>>), anyhow::Error> {
        if tls {
            let cert = X509::from_pem(std::fs::read_to_string("test-cert.pem")?.as_bytes())?;
            let pkey =
                PKey::private_key_from_pem(std::fs::read_to_string("test-key.pem")?.as_bytes())?;

            return Ok((Some(cert), Some(pkey)));
        }

        Ok((None, None))
    }

    fn create_resolvers(
        sockets: Vec<SocketAddr>,
        cert: Option<X509>,
        member_name: Name,
    ) -> Resolvers {
        let mut resolvers = Vec::new();

        for socket in sockets {
            let mut resolver_config = ResolverConfig::new();
            resolver_config.add_search(domain_or_default(None).unwrap());
            resolver_config.add_name_server(NameServerConfig {
                bind_addr: None,
                socket_addr: if cert.clone().is_some() {
                    SocketAddr::new(socket.ip(), 853)
                } else {
                    socket
                },
                protocol: if cert.clone().is_some() {
                    trust_dns_resolver::config::Protocol::Tls
                } else {
                    trust_dns_resolver::config::Protocol::Udp
                },
                tls_dns_name: if cert.clone().is_some() {
                    Some(member_name.to_string())
                } else {
                    None
                },
                trust_nx_responses: true,
            });

            let mut opts = ResolverOpts::default();
            opts.attempts = 10;
            opts.cache_size = 0;
            opts.rotate = true;
            opts.use_hosts_file = false;
            opts.positive_min_ttl = Some(Duration::new(0, 0));
            opts.positive_max_ttl = Some(Duration::new(0, 0));
            opts.negative_min_ttl = Some(Duration::new(0, 0));
            opts.negative_max_ttl = Some(Duration::new(0, 0));

            resolvers.push(Arc::new(
                trust_dns_resolver::TokioAsyncResolver::tokio(resolver_config, opts).unwrap(),
            ));
        }

        resolvers
    }

    async fn create_listeners(
        tn: &TestNetwork,
        hosts: HostsType,
        update_interval: Option<Duration>,
        wildcard_everything: bool,
        cert: Option<X509>,
        private_key: Option<PKey<Private>>,
    ) -> (
        Vec<SocketAddr>,
        Vec<JoinHandle<Result<(), anyhow::Error>>>,
        JoinHandle<()>,
    ) {
        let listen_cidrs = get_listen_ips(&authtoken_path(None), &tn.network.clone().id.unwrap())
            .await
            .unwrap();

        let mut listen_ips = Vec::new();

        let mut ipmap = HashMap::new();
        let mut authority_map = HashMap::new();

        for cidr in listen_cidrs.clone() {
            let listen_ip = parse_ip_from_cidr(cidr.clone());
            let socket_addr = SocketAddr::new(listen_ip.clone(), 53);
            listen_ips.push(socket_addr);
            let cidr = IpNetwork::from_str(&cidr.clone()).unwrap();
            if !ipmap.contains_key(&listen_ip) {
                ipmap.insert(listen_ip, cidr.network());
            }

            if !authority_map.contains_key(&cidr) {
                let ptr_authority = RecordAuthority::new(
                    cidr.to_ptr_soa_name().unwrap(),
                    cidr.to_ptr_soa_name().unwrap(),
                    cert.clone(),
                )
                .await
                .unwrap();
                authority_map.insert(cidr, ptr_authority.clone());
            }
        }

        if let Some(v6assign) = tn.network.config.clone().unwrap().v6_assign_mode {
            if v6assign.rfc4193.unwrap_or(false) {
                let cidr = tn.network.clone().rfc4193().unwrap();
                if !authority_map.contains_key(&cidr) {
                    let ptr_authority = RecordAuthority::new(
                        cidr.to_ptr_soa_name().unwrap(),
                        cidr.to_ptr_soa_name().unwrap(),
                        cert.clone(),
                    )
                    .await
                    .unwrap();
                    authority_map.insert(cidr, ptr_authority);
                }
            }
        }

        let authority = RecordAuthority::new(
            domain_or_default(None).unwrap().into(),
            tn.member()
                .to_fqdn(domain_or_default(None).unwrap().into())
                .unwrap()
                .into(),
            cert.clone(),
        )
        .await
        .unwrap();

        let update_interval = update_interval.unwrap_or(Duration::new(1, 0));

        let ztauthority = ZTAuthority {
            network_id: tn.network.clone().id.unwrap(),
            config: tn.central(),
            hosts_file: format_hosts_file(hosts),
            reverse_authority_map: authority_map,
            update_interval,
            forward_authority: authority.clone(),
            wildcard: wildcard_everything,
            hosts: None,
        };

        let authority_func = tokio::spawn(find_members(ztauthority.clone()));
        tokio::time::sleep(update_interval.add(Duration::new(3, 0))).await;

        let mut servers = Vec::new();

        for ip in listen_ips.clone() {
            let server = Server::new(ztauthority.to_owned());
            info!("Serving {}", ip.clone());
            let ca =
                X509::from_pem(std::fs::read_to_string("test-ca.pem").unwrap().as_bytes()).unwrap();
            let mut stack = Stack::new().unwrap();
            stack.push(ca).unwrap();

            servers.push(tokio::spawn(server.listen(
                ip.ip(),
                Duration::new(1, 0),
                cert.clone(),
                Some(stack),
                private_key.clone(),
            )));
        }

        (listen_ips, servers, authority_func)
    }

    pub fn any_listen_ip(self) -> IpAddr {
        self.listen_ips
            .clone()
            .into_iter()
            .choose(&mut rand::thread_rng())
            .unwrap()
            .clone()
            .ip()
    }

    pub fn network(&self) -> Arc<TestNetwork> {
        self.tn.clone()
    }

    pub fn resolvers(&self) -> Resolvers {
        self.resolvers.clone()
    }

    pub fn any_resolver(&self) -> Arc<Resolver> {
        self.resolvers()
            .choose(&mut rand::thread_rng())
            .to_owned()
            .unwrap()
            .clone()
    }

    pub fn member_record(&self) -> String {
        format!("zt-{}.home.arpa.", self.network().identity().clone())
    }

    pub async fn change_name(&self, name: &'static str) {
        let mut member = zerotier_central_api::apis::network_member_api::get_network_member(
            &self.network().central(),
            &self.network().network.clone().id.unwrap(),
            &self.network().identity(),
        )
        .await
        .unwrap();

        member.name = Some(name.to_string());

        zerotier_central_api::apis::network_member_api::update_network_member(
            &self.network().central(),
            &self.network().network.clone().id.unwrap(),
            &self.network().identity(),
            member,
        )
        .await
        .unwrap();

        if self.update_interval.is_some() {
            tokio::time::sleep(self.update_interval.unwrap()).await; // wait for it to update
        }
    }

    pub fn test_network(&self) -> Arc<TestNetwork> {
        self.tn.clone()
    }
}

#[async_trait]
impl Lookup for Service {
    async fn lookup_a(&self, record: String) -> Vec<Ipv4Addr> {
        self.any_resolver().lookup_a(record).await
    }

    async fn lookup_aaaa(&self, record: String) -> Vec<Ipv6Addr> {
        self.any_resolver().lookup_aaaa(record).await
    }

    async fn lookup_ptr(&self, record: String) -> Vec<String> {
        self.any_resolver().lookup_ptr(record).await
    }
}
