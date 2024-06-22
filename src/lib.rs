use hickory_client::client::{Client, SyncClient};
use hickory_client::op::DnsResponse;
use hickory_client::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_client::tcp::TcpClientConnection;
use rustdns::util::reverse;
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub struct PtrResult {
    pub query_addr: IpAddr,
    pub query: Name,
    pub result: Option<Name>,
    pub error: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IpToResolve {
    pub address: IpAddr,
    pub server: SocketAddr,
}

pub fn get_ptr(to_resolve: IpToResolve, client: SyncClient<TcpClientConnection>) -> PtrResult {
    // Specify the name, note the final '.' which specifies it's an FQDN
    let name = match Name::from_str(&reverse(to_resolve.address)) {
        Ok(name) => name,
        Err(err) => {
            eprintln!(
                "Something went wrong while building the name ({}): {}",
                reverse(to_resolve.address),
                err
            );
            process::exit(1);
        }
    };
    ptr_resolve(name, to_resolve, client)
}

/**
 * This will resolve a name into its DNS pointer value
 * The to_resolve argument will not really be used, but is needed for PtrResult
 */
pub fn ptr_resolve(
    name: Name,
    to_resolve: IpToResolve,
    client: SyncClient<TcpClientConnection>,
) -> PtrResult {
    let response: DnsResponse = match client.query(&name, DNSClass::IN, RecordType::PTR) {
        Ok(res) => res,
        Err(err) => {
            let two_hundred_millis = Duration::from_millis(400);
            thread::sleep(two_hundred_millis);
            eprintln!(
                "Query error for ({}) from ({}): {}",
                name, to_resolve.server, err
            );
            return PtrResult {
                query_addr: to_resolve.address,
                query: name,
                result: None,
                error: Some(err.to_string()),
            };
        }
    };

    let answers: &[Record] = response.answers();

    if answers.len() == 0 {
        return PtrResult {
            query_addr: to_resolve.address,
            query: name,
            result: None,
            error: None,
        };
    }

    match answers[0].data() {
        Some(RData::PTR(res)) => {
            return PtrResult {
                query_addr: to_resolve.address,
                query: name,
                result: Some(res.to_lowercase()),
                error: None,
            };
        }
        // Example: 87.246.7.75
        // Replies:
        // 75.7.246.87.in-addr.arpa. 3600	IN	CNAME	75.0-255.7.246.87.in-addr.arpa.
        // 75.0-255.7.246.87.in-addr.arpa.	86400 IN PTR	bulbank.linkbg.com.
        Some(RData::CNAME(res)) => {
            return ptr_resolve(res.to_lowercase(), to_resolve, client);
        }
        Some(res) => {
            eprintln!(
                "Unexpected result ({:?}) for ({}) from: {}",
                res, name, to_resolve.server
            );
            process::exit(1);
        }
        None => {
            eprintln!(
                "Weird empty result for ({}) from: {}",
                name, to_resolve.server
            );
            return PtrResult {
                query_addr: to_resolve.address,
                query: name,
                result: None,
                error: None,
            };
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_ptr() {
        let server = "8.8.8.8:53".parse().expect("To parse");
        let conn = match TcpClientConnection::with_timeout(server, Duration::new(5, 0)) {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!(
                    "Something went wrong with the UDP client connection: {}",
                    err
                );
                process::exit(1);
            }
        };
        let client = SyncClient::new(conn);

        let query_address = "8.8.8.8".parse().expect("To parse");

        assert_eq!(
            get_ptr(
                IpToResolve {
                    address: query_address,
                    server: server,
                },
                client
            ),
            PtrResult {
                query_addr: query_address,
                query: Name::from_str_relaxed("8.8.8.8.in-addr.arpa.").unwrap(),
                result: Some(Name::from_str_relaxed("dns.google.").unwrap()),
                error: None,
            }
        );
    }

    #[test]
    fn test_ptr_resolve() {
        let server = "1.1.1.1:53".parse().expect("To parse");
        let conn = match TcpClientConnection::with_timeout(server, Duration::new(5, 0)) {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!(
                    "Something went wrong with the UDP client connection: {}",
                    err
                );
                process::exit(1);
            }
        };
        let client = SyncClient::new(conn);

        let name_to_resolve = Name::from_str_relaxed("1.1.1.1.in-addr.arpa.").unwrap();
        let query_ip_unused = "127.0.0.1".parse().expect("To parse");

        assert_eq!(
            ptr_resolve(
                name_to_resolve.clone(),
                IpToResolve {
                    address: query_ip_unused,
                    server: server,
                },
                client
            ),
            PtrResult {
                query_addr: query_ip_unused,
                query: name_to_resolve,
                result: Some(Name::from_str_relaxed("one.one.one.one.").unwrap()),
                error: None,
            }
        );
    }

    #[test]
    fn test_reverse_dns() {
        assert_eq!(
            reverse("192.0.2.12".parse().unwrap()),
            "12.2.0.192.in-addr.arpa."
        );
    }
}
