use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Sender, channel, error::SendError};
use tokio_stream::{Stream, wrappers::ReceiverStream};

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
    receiver: ReceiverStream<Message>,
}

impl UdpStream {
    pub fn new(socket: UdpSocket) -> UdpStream {
        let (sender, receiver) = channel(10);

        UdpStream {
            socket,
            sender,
            receiver: ReceiverStream::new(receiver),
        }
    }

    fn split(&mut self) -> (&mut UdpSocket, &mut ReceiverStream<Message>) {
        (&mut self.socket, &mut self.receiver)
    }
}

impl Stream for UdpStream {
    type Item = Result<(Vec<u8>, Responder), std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let (socket, receiver) = self.split();
        let mut receiver = Pin::new(receiver);

        while let Poll::Ready(Some(Message { data, addr })) = receiver.as_mut().poll_next(cx) {
            match socket.poll_send_to(cx, &data, addr) {
                Poll::Pending => break,
                Poll::Ready(Err(e)) => {
                    tracing::error!(error = %e, addr = %addr, "error sending dns response");
                }
                Poll::Ready(_) => {}
            }
        }

        let mut buf = [0u8; 512];
        let mut buf = ReadBuf::new(&mut buf);
        match socket.poll_recv_from(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(Some(result.map(|addr| {
                let data = buf.filled().to_vec();
                let sender = self.sender.clone();
                let responder = Responder { sender, addr };
                (data, responder)
            }))),
        }
    }
}
