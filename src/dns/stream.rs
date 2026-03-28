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

    pub async fn send(&self, data: Vec<u8>) -> Result<(), SendError<()>> {
        let message = Message {
            data,
            addr: self.addr,
        };
        let permit = self.sender.reserve().await?;
        permit.send(message);
        Ok(())
    }
}

#[derive(Debug)]
pub struct UdpStream {
    socket: UdpSocket,
    sender: Sender<Message>,
    receiver: Receiver<Message>,
}

impl UdpStream {
    pub fn new(socket: UdpSocket) -> UdpStream {
        let (sender, receiver) = channel(10);

        UdpStream {
            socket,
            sender,
            receiver,
        }
    }

    fn split(&mut self) -> (&mut UdpSocket, &mut Receiver<Message>) {
        (&mut self.socket, &mut self.receiver)
    }

    pub async fn next(&mut self) -> std::io::Result<(Vec<u8>, Responder)> {
        let (socket, receiver) = self.split();

        while let Ok(Message { data, addr }) = receiver.try_recv() {
            match socket.send_to(&data, addr).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!(error = %e, addr = %addr, "error sending UDP response");
                }
            }
        }

        let mut buf = [0u8; 512];
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let data = buf[..len].to_vec();
                let sender = self.sender.clone();
                let responder = Responder { sender, addr };
                Ok((data, responder))
            }
            Err(e) => {
                tracing::error!(error = %e,"error receiving UDP request");
                Err(e)
            }
        }
    }
}
