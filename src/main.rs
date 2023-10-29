use hickory_client::client::{ Client, SyncClient };
use hickory_client::tcp::TcpClientConnection;
use std::str::FromStr;
use std::net::IpAddr;
use hickory_client::op::DnsResponse;
use hickory_client::rr::{ DNSClass, Name, RData, Record, RecordType };
use rustdns::util::reverse;
use rayon::prelude::*;
use std::fs::read_to_string;
use std::env;
use std::process;
use std::net::SocketAddr;
use weighted_rs::{ RoundrobinWeight, Weight };
use std::time::Duration;
use std::thread;

struct PtrResult {
    query_addr: IpAddr,
    query: Name,
    result: Option<Name>,
    error: Option<String>,
}

#[derive(Copy, Clone)]
struct IpToResolve {
    address: IpAddr,
    server: SocketAddr,
}

fn get_ptr(to_resolve: IpToResolve, client: SyncClient<TcpClientConnection>) -> PtrResult {
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

fn ptr_resolve(
    name: Name,
    to_resolve: IpToResolve,
    client: SyncClient<TcpClientConnection>
) -> PtrResult {
    let response: DnsResponse = match client.query(&name, DNSClass::IN, RecordType::PTR) {
        Ok(res) => res,
        Err(err) => {
            let two_hundred_millis = Duration::from_millis(400);
            thread::sleep(two_hundred_millis);
            eprintln!("Query error for ({}) from ({}): {}", name, to_resolve.server, err);
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
            eprintln!("Unexpected result ({:?}) for ({}) from: {}", res, name, to_resolve.server);
            process::exit(1);
        }
        None => {
            eprintln!("Weird empty result for ({}) from: {}", name, to_resolve.server);
            return PtrResult {
                query_addr: to_resolve.address,
                query: name,
                result: None,
                error: None,
            };
        }
    }
}

fn resolve_file(filename: &str, dns_servers: Vec<&str>) {
    let mut rr: RoundrobinWeight<SocketAddr> = RoundrobinWeight::new();
    for dns_server in dns_servers {
        let address = match dns_server.parse() {
            Ok(addr) => addr,
            Err(err) => {
                eprintln!("Something went wrong while parsing the DNS server address: {}", err);
                process::exit(1);
            }
        };

        rr.add(address, 1);
    }

    let mut ips = vec![];
    match read_to_string(filename) {
        Ok(file) => {
            for line in file.lines() {
                match IpAddr::from_str(line) {
                    Ok(addr) =>
                        ips.push(IpToResolve {
                            address: addr,
                            server: rr.next().unwrap(),
                        }),
                    Err(err) => {
                        eprintln!("Something went wrong while parsing the IP ({}): {}", line, err);
                        process::exit(1);
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("Something went wrong while reading the file: {}", err);
            process::exit(1);
        }
    }
    match rayon::ThreadPoolBuilder::new().num_threads(30).build_global() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("Something went wrong while building the thread pool: {}", err);
            process::exit(1);
        }
    }

    ips.into_par_iter()
        .enumerate()
        .for_each(|(_i, to_resolve)| {
            let conn = match
                TcpClientConnection::with_timeout(to_resolve.server, Duration::new(5, 0))
            {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!("Something went wrong with the UDP client connection: {}", err);
                    process::exit(1);
                }
            };
            let client = SyncClient::new(conn);
            match get_ptr(to_resolve, client).result {
                Some(res) => println!("{} # {}", to_resolve.address, res),
                None => println!("{}", to_resolve.address),
            };
        });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Use: dns-ptr-resolver ./ips.txt");
        process::exit(1);
    }
    resolve_file(&args[1], vec!["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"])
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_reverse_dns() {
        assert_eq!(reverse("192.0.2.12".parse().unwrap()), "12.2.0.192.in-addr.arpa.");
    }

    #[test]
    fn test_resolve_file() {
        resolve_file("./example/ips-to-resolve.txt", vec!["1.1.1.1:53"]);
    }
}
