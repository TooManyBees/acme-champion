use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[derive(Clone, Debug)]
pub struct Responder {
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
}

impl Responder {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn send(&self, data: Vec<u8>) -> std::io::Result<()> {
        self.socket.send_to(&data, self.addr).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct UdpStream {
    socket: Arc<UdpSocket>,
}

impl UdpStream {
    pub fn new(socket: Arc<UdpSocket>) -> UdpStream {
        UdpStream {
            socket,
        }
    }

    pub async fn next(&mut self) -> std::io::Result<(Vec<u8>, Responder)> {
        let mut buf = [0u8; 512];
        match self.socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let data = buf[..len].to_vec();
                let responder = Responder { addr, socket: self.socket.clone() };
                Ok((data, responder))
            }
            Err(e) => {
                tracing::error!(error = %e,"error receiving UDP request");
                Err(e)
            }
        }
    }
}
