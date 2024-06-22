use hickory_client::client::{Client, SyncClient};
use hickory_client::op::DnsResponse;
use hickory_client::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_client::tcp::TcpClientConnection;
use rustdns::util::reverse;
use std::net::IpAddr;
use std::str::FromStr;
use std::{error::Error, fmt};

#[derive(Clone, Debug, PartialEq)]
/// The result of resolving the pointer or the IP
pub struct ResolvedResult {
    /// For example: one.one.one.one.
    /// For example: dns.google.
    pub query: Name,
    /// For example: 1.1.1.1.in-addr.arpa.
    /// For example: 8.8.8.8.in-addr.arpa.
    pub result: Option<Name>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct ResolvingError {
    pub message: String,
}

impl Error for ResolvingError {}

impl fmt::Display for ResolvingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

/**
 * Resolve a DNS IP adddress (IPv4/IPv6) into a DNS pointer
 * ```
 * use hickory_client::client::SyncClient;
 * use hickory_client::rr::Name;
 * use hickory_client::tcp::TcpClientConnection;
 *
 * use dns_ptr_resolver::{get_ptr, ResolvedResult};
 *
 * let server = "1.1.1.1:53".parse().expect("To parse");
 * let conn = TcpClientConnection::with_timeout(server, std::time::Duration::new(5, 0)).unwrap();
 * let client = SyncClient::new(conn);
 * let query_address = "8.8.8.8".parse().expect("To parse");
 *
 * assert_eq!(
 *  get_ptr(query_address, client).unwrap(),
 *  ResolvedResult {
 *      query: Name::from_str_relaxed("8.8.8.8.in-addr.arpa.").unwrap(),
 *      result: Some(Name::from_str_relaxed("dns.google.").unwrap()),
 *      error: None,
 *  }
 * );
 * ```
 */
pub fn get_ptr(
    ip_address: IpAddr,
    client: SyncClient<TcpClientConnection>,
) -> Result<ResolvedResult, ResolvingError> {
    // Specify the name, note the final '.' which specifies it's an FQDN
    match Name::from_str(&reverse(ip_address)) {
        Ok(name) => ptr_resolve(name, client),
        Err(err) => Err(ResolvingError {
            message: format!(
                "Something went wrong while building the name ({}): {}",
                reverse(ip_address),
                err
            ),
        }),
    }
}

/**
 * This will resolve a name into its DNS pointer value
 * ```
 * use hickory_client::client::SyncClient;
 * use hickory_client::rr::Name;
 * use hickory_client::tcp::TcpClientConnection;
 *
 * use dns_ptr_resolver::{ptr_resolve, ResolvedResult};
 *
 * let server = "8.8.8.8:53".parse().expect("To parse");
 * let conn = TcpClientConnection::with_timeout(server, std::time::Duration::new(5, 0)).unwrap();
 * let client = SyncClient::new(conn);
 *
 * let name_to_resolve = Name::from_str_relaxed("1.1.1.1.in-addr.arpa.").unwrap();
 *
 * assert_eq!(
 *  ptr_resolve(name_to_resolve.clone(), client).unwrap(),
 *  ResolvedResult {
 *      query: name_to_resolve,
 *      result: Some(Name::from_str_relaxed("one.one.one.one.").unwrap()),
 *      error: None,
 *  }
 * );
 * ```
 */
pub fn ptr_resolve(
    name: Name,
    client: SyncClient<TcpClientConnection>,
) -> Result<ResolvedResult, ResolvingError> {
    let response: DnsResponse = match client.query(&name, DNSClass::IN, RecordType::PTR) {
        Ok(res) => res,
        Err(err) => {
            return Err(ResolvingError {
                message: format!("Query error for ({}): {}", name, err),
            })
        }
    };

    let answers: &[Record] = response.answers();

    if answers.len() == 0 {
        return Ok(ResolvedResult {
            query: name,
            result: None,
            error: None,
        });
    }

    match answers[0].data() {
        Some(RData::PTR(res)) => {
            return Ok(ResolvedResult {
                query: name,
                result: Some(res.to_lowercase()),
                error: None,
            });
        }
        // Example: 87.246.7.75
        // Replies:
        // 75.7.246.87.in-addr.arpa. 3600	IN	CNAME	75.0-255.7.246.87.in-addr.arpa.
        // 75.0-255.7.246.87.in-addr.arpa.	86400 IN PTR	bulbank.linkbg.com.
        Some(RData::CNAME(res)) => {
            return ptr_resolve(res.to_lowercase(), client);
        }
        Some(res) => {
            return Err(ResolvingError {
                message: format!("Unexpected result ({:?}) from: {}", res, name),
            });
        }
        None => {
            return Err(ResolvingError {
                message: format!("Weird empty result from: {}", name),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::process;
    use std::time::Duration;

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
            get_ptr(query_address, client).unwrap(),
            ResolvedResult {
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

        assert_eq!(
            ptr_resolve(name_to_resolve.clone(), client).unwrap(),
            ResolvedResult {
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
