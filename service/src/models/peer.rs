/*
 * ZeroTierOne Service API
 *
 * <p> This API controls the ZeroTier service that runs in the background on your computer. This is how zerotier-cli, and the macOS and Windows apps control the service. </p> <p> API requests must be authenticated via an authentication token. ZeroTier One saves this token in the authtoken.secret file in its working directory. This token may be supplied via the X-ZT1-Auth HTTP request header. </p> <p> For example: <code>curl -H \"X-ZT1-Auth: $TOKEN\" http://localhost:9993/status</code> </p> <p> The token can be found in: <ul> <li>Mac :: /Library/Application Support/ZeroTier/One</li> <li>Windows :: \\ProgramData\\ZeroTier\\One</li> <li>Linux :: /var/lib/zerotier-one</li> </ul> </p> 
 *
 * The version of the OpenAPI document: 0.1.0
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Peer {
    #[serde(rename = "address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "isBonded", skip_serializing_if = "Option::is_none")]
    pub is_bonded: Option<bool>,
    #[serde(rename = "latency", skip_serializing_if = "Option::is_none")]
    pub latency: Option<i32>,
    #[serde(rename = "paths", skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<crate::models::PeerPaths>>,
    #[serde(rename = "role", skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(rename = "version", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "versionMajor", skip_serializing_if = "Option::is_none")]
    pub version_major: Option<i32>,
    #[serde(rename = "versionMinor", skip_serializing_if = "Option::is_none")]
    pub version_minor: Option<i32>,
    #[serde(rename = "versionRev", skip_serializing_if = "Option::is_none")]
    pub version_rev: Option<i32>,
}

impl Peer {
    pub fn new() -> Peer {
        Peer {
            address: None,
            is_bonded: None,
            latency: None,
            paths: None,
            role: None,
            version: None,
            version_major: None,
            version_minor: None,
            version_rev: None,
        }
    }
}


