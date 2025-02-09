# Rust API client for service

<p> This API controls the ZeroTier service that runs in the background on your computer. This is how zerotier-cli, and the macOS and Windows apps control the service. </p> <p> API requests must be authenticated via an authentication token. ZeroTier One saves this token in the authtoken.secret file in its working directory. This token may be supplied via the X-ZT1-Auth HTTP request header. </p> <p> For example: <code>curl -H \"X-ZT1-Auth: $TOKEN\" http://localhost:9993/status</code> </p> <p> The token can be found in: <ul> <li>Mac :: /Library/Application Support/ZeroTier/One</li> <li>Windows :: \\ProgramData\\ZeroTier\\One</li> <li>Linux :: /var/lib/zerotier-one</li> </ul> </p> 

## Overview

This API client was generated by the [OpenAPI Generator](https://openapi-generator.tech) project.  By using the [openapi-spec](https://openapis.org) from a remote server, you can easily generate an API client.

- API version: 0.1.0
- Package version: 1.0.0
- Build package: org.openapitools.codegen.languages.RustClientCodegen

## Installation

Put the package under your project folder and add the following to `Cargo.toml` under `[dependencies]`:

```
    openapi = { path = "./generated" }
```

## Documentation for API Endpoints

All URIs are relative to *http://localhost:9993*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*NetworkApi* | [**delete_network**](docs/NetworkApi.md#delete_network) | **delete** /network/{networkID} | Leave a network
*NetworkApi* | [**get_network**](docs/NetworkApi.md#get_network) | **get** /network/{networkID} | Gets a joined Network by ID.
*NetworkApi* | [**get_networks**](docs/NetworkApi.md#get_networks) | **get** /network | Get all network memberships.
*NetworkApi* | [**update_network**](docs/NetworkApi.md#update_network) | **post** /network/{networkID} | Join a network or update it's configuration
*PeerApi* | [**get_peer**](docs/PeerApi.md#get_peer) | **get** /peer/{address} | Get information about a specific peer.
*PeerApi* | [**get_peers**](docs/PeerApi.md#get_peers) | **get** /peer | Get all peers.
*StatusApi* | [**get_status**](docs/StatusApi.md#get_status) | **get** /status | Node status and addressing info.


## Documentation For Models

 - [Network](docs/Network.md)
 - [NetworkR](docs/NetworkR.md)
 - [NetworkRDns](docs/NetworkRDns.md)
 - [NetworkRMulticastSubscriptions](docs/NetworkRMulticastSubscriptions.md)
 - [NetworkRRoutes](docs/NetworkRRoutes.md)
 - [NetworkW](docs/NetworkW.md)
 - [Peer](docs/Peer.md)
 - [PeerPaths](docs/PeerPaths.md)
 - [Status](docs/Status.md)
 - [StatusConfig](docs/StatusConfig.md)
 - [StatusConfigSettings](docs/StatusConfigSettings.md)


To get access to the crate's generated documentation, use:

```
cargo doc --open
```

## Author



