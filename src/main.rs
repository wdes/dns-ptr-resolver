use std::{env, thread};

use dns_ptr_resolver::get_ptr;
use hickory_client::client::SyncClient;
use hickory_client::tcp::TcpClientConnection;
use rayon::prelude::*;
use std::fs::read_to_string;
use std::net::{IpAddr, SocketAddr};
use std::process;
use std::str::FromStr;
use std::time::Duration;
use weighted_rs::{RoundrobinWeight, Weight};

#[derive(Copy, Clone, Debug, PartialEq)]
struct IpToResolve {
    pub address: IpAddr,
    pub server: SocketAddr,
}

fn resolve_file(filename: &str, dns_servers: Vec<&str>) {
    let mut rr: RoundrobinWeight<SocketAddr> = RoundrobinWeight::new();
    for dns_server in dns_servers {
        let address = match dns_server.parse() {
            Ok(addr) => addr,
            Err(err) => {
                eprintln!(
                    "Something went wrong while parsing the DNS server address: {}",
                    err
                );
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
                    Ok(addr) => ips.push(IpToResolve {
                        address: addr,
                        server: rr.next().unwrap(),
                    }),
                    Err(err) => {
                        eprintln!(
                            "Something went wrong while parsing the IP ({}): {}",
                            line, err
                        );
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
    match rayon::ThreadPoolBuilder::new()
        .num_threads(30)
        .build_global()
    {
        Ok(r) => r,
        Err(err) => {
            eprintln!(
                "Something went wrong while building the thread pool: {}",
                err
            );
            process::exit(1);
        }
    }

    ips.into_par_iter()
        .enumerate()
        .for_each(|(_i, to_resolve)| {
            let conn =
                match TcpClientConnection::with_timeout(to_resolve.server, Duration::new(5, 0)) {
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
            let ptr_result = get_ptr(to_resolve.address, client);
            match ptr_result {
                Ok(ptr) => match ptr.result {
                    Some(res) => println!("{} # {}", to_resolve.address, res),
                    None => println!("{}", to_resolve.address),
                },
                Err(err) => {
                    let two_hundred_millis = Duration::from_millis(400);
                    thread::sleep(two_hundred_millis);

                    eprintln!(
                        "[{}] Error for {} -> {}",
                        to_resolve.server, to_resolve.address, err.message
                    )
                }
            }
        });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Use: dns-ptr-resolver ./ips.txt");
        process::exit(1);
    }
    resolve_file(
        &args[1],
        vec!["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"],
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_resolve_file() {
        resolve_file("./example/ips-to-resolve.txt", vec!["1.1.1.1:53"]);
    }
}
