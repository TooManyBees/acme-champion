use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender, channel, error::SendError};

#[derive(Clone, Debug)]
pub struct Message {
    pub data: Vec<u8>,
    pub addr: SocketAddr,
}

#[derive(Clone, Debug)]
pub struct Responder {
    addr: SocketAddr,
    sender: Sender<Message>,
}

impl Responder {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), SendError<Message>> {
        let message = Message {
            data,
            addr: self.addr,
        };
        self.sender.send(message).await
    }
}

#[derive(Debug)]
pub struct UdpStream {
    socket: UdpSocket,
    sender: Sender<Message>,
    buf: [u8; 512],
}

impl UdpStream {
    pub fn new(socket: UdpSocket) -> (UdpStream, Receiver<Message>) {
        let (sender, receiver) = channel(10);

        (UdpStream { socket, sender , buf: [0u8; 512] }, receiver)
    }

    pub async fn recv_from(&mut self) -> io::Result<(Vec<u8>, Responder)> {
        self.socket.recv_from(&mut self.buf).await.map(|(len, addr)| {
            let data = self.buf[0..len].to_vec();
            let sender = self.sender.clone();
            let responder = Responder { sender, addr };
            (data, responder)
        })
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(buf, addr).await.map(|_| ())
    }
}
