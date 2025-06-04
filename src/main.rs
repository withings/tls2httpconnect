/* tls2httpconnect - intercept outgoing TLS and forward it to an HTTP proxy
 * Copyright (C) 2025 Withings
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>. */

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use async_http_proxy::{HttpError, http_connect_tokio};
use clap::Parser;
use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, TlsRecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use snafu::prelude::*;

const TLS_HEADER_SIZE: usize = 5;

#[derive(Parser)]
/// Listens for incoming TLS handshakes and issues HTTP CONNECT to an upstream proxy to relay the connection
struct Cli {
    /// Upstream proxy address
    proxy_addr: IpAddr,
    /// Upstream proxy port
    proxy_port: u16,
    /// Address to bind to when listening for incoming TLS handshakes
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))]
    bind_addr: IpAddr,
    /// Port to listen on for incoming TLS handshakes
    #[arg(long, default_value_t = 8888)]
    bind_port: u16,
    /// Port intercepted by NAT, also the outbound port used in HTTP CONNECT
    #[arg(long, default_value_t = 443)]
    connect_port: u16,
    /// Buffer size to use when relaying between the client and the upstream proxy
    #[arg(long, default_value_t = 8092)]
    buffer_size: usize,
}

#[derive(Debug, Snafu)]
/// Generic error enum for everything that can go wrong
enum RelayError {
    #[snafu(display("failed to set up the listening socket"))]
    Bind { source: std::io::Error },

    #[snafu(display("failed to accept an incoming connection"))]
    Incoming { source: std::io::Error },

    #[snafu(display("I/O error with the client"))]
    ClientIO { source: std::io::Error },

    #[snafu(display("the client sent an incomplete TLS header, got {header_bytes_read} byte(s)"))]
    IncompleteTlsHeader { header_bytes_read: usize },

    #[snafu(display("the client sent an invalid TLS header"))]
    InvalidTlsHeader,

    #[snafu(display("the client did not start with a TLS handshake"))]
    NoHandshake,

    #[snafu(display("the client sent an incomplete TLS record"))]
    IncompleteTlsRecord,

    #[snafu(display("the client sent an invalid TLS record"))]
    InvalidTlsRecord,

    #[snafu(display("the client did not start with a ClientHello message"))]
    MissingClientHello,

    #[snafu(display("the client sent invalid ClientHello extensions"))]
    InvalidClientExtensions,

    #[snafu(display("the client either provided no SNI or provided more than one"))]
    MissingSNI,

    #[snafu(display("the client provided a non-UTF-8 SNI"))]
    SNIEncoding,

    #[snafu(display("I/O error with the proxy: {source}"))]
    ProxyIO { source: std::io::Error },

    #[snafu(display("failed to set up HTTP connect to the proxy: {source}"))]
    HttpConnect { source: HttpError },
}

#[tokio::main(flavor="current_thread")]
#[snafu::report]
async fn main() -> Result<(), RelayError> {
    env_logger::init();

    let cli = Cli::parse();
    let socket_addr = SocketAddr::new(cli.bind_addr, cli.bind_port);
    let listener = TcpListener::bind(socket_addr).await.context(BindSnafu)?;
    log::info!("ready for incoming connections at {}", socket_addr);

    if !cli.bind_addr.is_loopback() {
        log::warn!("not listening on a local address, you may be running an open proxy!");
    }

    loop {
        let (socket, addr) = listener.accept().await.context(IncomingSnafu)?;
        tokio::spawn(async move {
            let sni = match peek_sni(&socket).await {
                Ok(n) => n,
                Err(e) => {
                    log::error!("{}: could not set up incoming connection: {}", addr, e);
                    return
                }
            };

            log::debug!("incoming connection received from {} to {}:{}", addr, sni, cli.connect_port);

            match run_http_connect_tunnel(socket, cli.proxy_addr, cli.proxy_port, &sni, cli.connect_port, cli.buffer_size).await {
                Ok(_) => log::info!("{} to {}:{}: relay complete", addr, sni, cli.connect_port),
                Err(e) => log::error!("{} to {}:{}: error: {}", addr, sni, cli.connect_port, e)
            }
        });
    }
}

async fn peek_sni(client_stream: &TcpStream) -> Result<String, RelayError> {
    /* Peek at the first 5 bytes to see if we're receiving a TLS handshake record */
    let mut tls_header_bytes = [0; TLS_HEADER_SIZE];
    let header_bytes_read = client_stream.peek(&mut tls_header_bytes).await.context(ClientIOSnafu)?;
    ensure!(header_bytes_read == TLS_HEADER_SIZE, IncompleteTlsHeaderSnafu { header_bytes_read });

    let (_, tls_header) = tls_parser::parse_tls_record_header(&tls_header_bytes)
        .map_err(|_| InvalidTlsHeaderSnafu.build())?;
    if tls_header.record_type != TlsRecordType::Handshake {
        return NoHandshakeSnafu.fail();
    }

    /* Peek at the entire ClientHello record */
    let client_hello_length: usize = TLS_HEADER_SIZE + (tls_header.len as usize);
    let mut client_hello_bytes = vec![0; client_hello_length];
    let client_hello_bytes_read = client_stream.peek(&mut client_hello_bytes).await.context(ClientIOSnafu)?;
    ensure!(client_hello_bytes_read == client_hello_length, IncompleteTlsRecordSnafu);

    /* Parse the ClientHello record, expect a handshake */
    let (_, tls_record) = tls_parser::parse_tls_plaintext(&client_hello_bytes)
        .map_err(|_| InvalidTlsRecordSnafu.build())?;
    let client_hello = tls_record.msg.iter().filter_map(|msg| match msg {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => Some(ch),
        _ => None
    }).next().ok_or(MissingClientHelloSnafu.build())?;

    /* Get the extensions in the ClientHello, then the SNI */
    let client_hello_exts_bytes = client_hello.ext.ok_or(RelayError::MissingSNI)?;
    let (_, client_hello_exts) = tls_parser::parse_tls_client_hello_extensions(client_hello_exts_bytes)
        .map_err(|_| InvalidClientExtensionsSnafu.build())?;
    let sni_ext = client_hello_exts.iter().filter_map(|ext| match ext {
        TlsExtension::SNI(snis) => Some(snis),
        _ => None
    }).next().ok_or(MissingSNISnafu.build())?;
    if sni_ext.len() != 1 {
        return MissingSNISnafu.fail();
    }

    Ok(String::from_utf8(sni_ext[0].1.to_vec()).map_err(|_| SNIEncodingSnafu.build())?)
}

async fn run_http_connect_tunnel(
    mut client_stream: TcpStream,
    proxy_addr: IpAddr,
    proxy_port: u16,
    server_name: &str,
    target_port: u16,
    buffer_size: usize,
) -> Result<(), RelayError> {
    /* Send HTTP CONNECT to the proxy, get a TCP tunnel going */
    let mut proxy_stream = TcpStream::connect((proxy_addr, proxy_port)).await.context(ProxyIOSnafu)?;
    http_connect_tokio(&mut proxy_stream, &server_name, target_port).await.context(HttpConnectSnafu)?;

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut proxy_read, mut proxy_write) = proxy_stream.split();
    let mut client_buffer = vec![0 as u8; buffer_size];
    let mut proxy_buffer = vec![0 as u8; buffer_size];

    /* Simply relay TCP between client and proxy */
    loop {
        tokio::select! {
            client_bytes_read = client_read.read(&mut client_buffer) => {
                match client_bytes_read {
                    Ok(n) => {
                        if let Err(_) = proxy_write.write(&client_buffer[..n]).await {
                            break;
                        }
                    },
                    Err(_) => break
                }
            },
            proxy_bytes_read = proxy_read.read(&mut proxy_buffer) => {
                match proxy_bytes_read {
                    Ok(n) => {
                        if let Err(_) = client_write.write(&proxy_buffer[..n]).await {
                            break;
                        }
                    },
                    Err(_) => break
                }
            }
        }
    }

    client_write.shutdown().await.ok();
    proxy_write.shutdown().await.ok();
    Ok(())
}
