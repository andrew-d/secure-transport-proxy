extern crate ansi_term;
extern crate clap;
extern crate fern;
#[macro_use] extern crate log;
extern crate security_framework;
extern crate time;

use std::convert::From;
use std::env;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use clap::{App, Arg, ArgMatches};
use security_framework::base;
use security_framework::item::{ItemClass, ItemSearchOptions, Reference};
use security_framework::identity::SecIdentity;
use security_framework::secure_transport::{self, ConnectionType, ProtocolSide, SslContext};

mod logger;


enum Error {
    IoError(io::Error),
    HandshakeError(secure_transport::HandshakeError<TcpStream>),
    SecurityError(base::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<secure_transport::HandshakeError<TcpStream>> for Error {
    fn from(e: secure_transport::HandshakeError<TcpStream>) -> Error {
        Error::HandshakeError(e)
    }
}

impl From<base::Error> for Error {
    fn from(e: base::Error) -> Error {
        Error::SecurityError(e)
    }
}


struct Config {
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    upstream_hostname: String,
    identity: SecIdentity,
    timeout: i64,
}

fn handle_connection(mut client_conn: TcpStream, config: Arc<Config>) -> Result<(), Error> {
    let peer = match client_conn.peer_addr() {
        Ok(a) => format!("{}", a),
        Err(_) => "<unknown>".to_string(),
    };
    info!("Got new connection from: {}", peer);

    // Dial the upstream address.
    let mut upstream_conn = try!(TcpStream::connect(config.upstream_addr));

    // Start SSL
    let mut ctx = try!(SslContext::new(ProtocolSide::Client, ConnectionType::Stream));
    try!(ctx.set_peer_domain_name("todo"));
    try!(ctx.set_certificate(&config.identity, &[]));

    let mut upstream_conn = try!(ctx.handshake(upstream_conn));

    // TODO: copy from one to the other.

    Ok(())
}

fn main() {
    let config = App::new("secure-transport-proxy")
        .version("0.0.1")
        .author("Andrew Dunham <andrew@du.nham.ca>")
        .about("Proxy that allows applications to use Apple's SecureTransport")
        .arg(Arg::with_name("debug")
             .short("d")
             .multiple(true)
             .help("Sets the level of debugging information"))
        .arg(Arg::with_name("timeout")
             .short("t")
             .long("timeout")
             .help("Idle timeout (in milliseconds) until we drop a connection"))
        .arg(Arg::with_name("identity")
             .short("i")
             .help("Specify the identity to use for outbound connections, defaults to current username"))
        .arg(Arg::with_name("listen")
             .index(1)
             .help("The listen address in host:port form"))
        .arg(Arg::with_name("upstream")
             .index(2)
             .help("The upstream address in host:port form"));

    // Actually parse
    let matches = config.get_matches();
    logger::init_logger_config(&matches);

    let config = match make_config(&matches) {
        Some(c) => Arc::new(c),
        None => return,
    };

    let listener = match TcpListener::bind(&config.listen_addr) {
        Ok(l) => l,
        Err(e) => {
            error!("Could not bind TCP listener to '{}': {}", config.listen_addr, e);
            return;
        },
    };

    info!("Starting proxy server on {:?}", listener.local_addr().unwrap());

    for stream in listener.incoming() {
        let c = config.clone();
        let conn = match stream {
            Ok(c) => c,
            Err(e) => {
                error!("Error accepting connection: {}", e);
                continue;
            },
        };

        thread::spawn(move || {
            handle_connection(conn, c)
        });
    }
}

fn make_config(matches: &ArgMatches) -> Option<Config> {
    macro_rules! extract_addr {
        ($arg: ident) => ({
            let arg_name = stringify!($arg);

            let v = match matches.value_of(arg_name) {
                Some(v) => v,
                None => {
                    error!("No value for argument '{}'", arg_name);
                    return None;
                },
            };

            let mut addrs = match v.to_socket_addrs() {
                Ok(i) => i,
                Err(e) => {
                    error!("Invalid address for argument '{}': {}", arg_name, e);
                    return None;
                },
            };

            match addrs.next() {
                Some(a) => a,
                None => {
                    error!("Unknown error - no address found for argument '{}': {}", arg_name, v);
                    return None;
                },
            }
        })
    };

    let listen_addr = extract_addr!(listen);
    let upstream_addr = extract_addr!(upstream);
    let upstream_hostname = {
        let v = match matches.value_of("upstream") {
            Some(v) => v,
            None => unreachable!(),
        };

        String::from(v.split(':').next().unwrap())
    };
    let timeout = {
        let s = matches.value_of("timeout").unwrap_or("1000");
        match FromStr::from_str(s) {
            Ok(v) => v,
            Err(e) => {
                error!("Invalid timeout '{}': {}", s, e);
                return None;
            },
        }
    };

    let current_user = match env::var("USER") {
        Ok(v) => v,
        Err(_) => String::new(),
    };
    let identity_name = matches.value_of("identity").unwrap_or(&*current_user);
    if identity_name.len() == 0 {
        error!("No identity given, and cannot get the current user.");
        return None;
    }

    let identity = match find_identity_by_name(identity_name) {
        Some(i) => i,
        None => return None,
    };

    Some(Config {
        listen_addr: listen_addr,
        upstream_addr: upstream_addr,
        upstream_hostname: upstream_hostname,
        identity: identity,
        timeout: timeout,
    })
}

fn find_identity_by_name(name: &str) -> Option<SecIdentity> {
    let items = ItemSearchOptions::new()
        .class(ItemClass::Identity)
        .load_refs(true)
        .search();
    let items = match items {
        Ok(i) => i,
        Err(e) => {
            error!("Could not search for identities: {}", e);
            return None;
        },
    };

    let result = match items.first() {
        Some(r) => r,
        None => return None,
    };

    let id = match result.reference {
        Some(Reference::Identity(i)) => i,
        Some(..) => {
            error!("Invalid reference type found");
            return None;
        },
        None => {
            error!("No reference found, but expected!");
            return None;
        },
    };

    Some(id)
}
