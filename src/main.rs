use trust_dns_client::client::{ Client, SyncClient };
use trust_dns_client::udp::UdpClientConnection;
use std::str::FromStr;
use std::net::IpAddr;
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{ DNSClass, Name, RData, Record, RecordType };
use rustdns::util::reverse;
use rayon::prelude::*;
use std::fs::read_to_string;
use std::env;
use std::process;

fn get_ptr(conn: UdpClientConnection, addr: IpAddr) {
    let client = SyncClient::new(conn);
    // Specify the name, note the final '.' which specifies it's an FQDN
    let name = Name::from_str(&reverse(addr)).unwrap();

    let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::PTR).unwrap();
    let answers: &[Record] = response.answers();

    if answers.len() == 0 {
        println!("{}", addr);
        return;
    }

    if let Some(RData::PTR(ref res)) = answers[0].data() {
        println!("{} # {}", addr, res);
    } else {
        assert!(false, "unexpected result")
    }
}

fn resolve_file(filename: &str, dns_server: &str) {
    let mut ips = vec![];
    match read_to_string(filename) {
        Ok(file) => {
            for line in file.lines() {
                match IpAddr::from_str(line) {
                    Ok(addr) => ips.push(addr),
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
    rayon::ThreadPoolBuilder::new().num_threads(50).build_global().unwrap();
    let address = dns_server.parse().unwrap();
    let conn = match UdpClientConnection::new(address) {
        Ok(conn) => conn,
        Err(err) => {
            eprintln!("Something went wrong with the UDP client connection: {}", err);
            process::exit(1);
        }
    };

    ips.into_par_iter()
        .enumerate()
        .for_each(|(_i, addr)| {
            get_ptr(conn, addr);
        });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Use: ptr-resolver ./ips.txt");
        process::exit(1);
    }
    resolve_file(&args[1], "1.1.1.1:53")
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
        resolve_file("./example/ips-to-resolve.txt", "1.1.1.1:53");
    }
}
