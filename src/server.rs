extern crate hyper;
extern crate rustc_serialize;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use hyper::Server;
use hyper::server::{Handler, Request, Response, Fresh};
use hyper::uri::RequestUri::AbsolutePath;
use std::net::{SocketAddrV4, Ipv4Addr};
use Runnable;
use std::str::FromStr;
use std::io::Write;
use std::io::Read;
use std::sync::Mutex;
use rustc_serialize::{json};
use packet::{PacketContainer, PingPacket};

pub struct CaptureServer {
    address: SocketAddrV4,
}

pub struct HttpHandler {
    sender: Mutex<Sender<String>>,
}

impl Handler for HttpHandler {
    fn handle<'a, 'k>(&'a self, req: Request<'a, 'k>, res: Response<'a, Fresh>) {
        let mut res = res.start().unwrap();
        let (_, _, _, requri, _, mut reader) = req.deconstruct();

        if let AbsolutePath(uri) = requri {
            if uri == "/api" {
                let mut buf: String = String::new();
                reader.read_to_string(&mut buf).expect("Could not read from HTTP-stream");
                self.sender.lock().unwrap().send(buf).unwrap();
            }
        } else {
            res.write_all(b"<html><head></head><body><h1>Unknown request</body></html>").unwrap();
        }

        res.end().unwrap();
    }
}

impl Runnable for CaptureServer {
    fn start(&mut self) {
        let address = self.address.clone();
        let (tx, rx) = channel();
        thread::spawn(move || {
            let result = Server::http(address).unwrap();
            result.handle(HttpHandler { sender: Mutex::new(tx) })
                  .expect("Could not start HTTP-handler");
        });
        thread::spawn(move || {
            loop {
                let data = rx.recv().unwrap();
                let packet: PacketContainer<PingPacket> = json::decode(&data).unwrap();
                for item in packet.data {
                    println!("{}|{}|{}|{}|{}", &packet.host_identifier, item.srcip, item.dstip, item.id, item.seq);
                }
            }
        });
    }

    fn exit(&mut self) {}
}

impl CaptureServer {
    pub fn new(ip: String, port: u16) -> CaptureServer {
        CaptureServer { address: SocketAddrV4::new(Ipv4Addr::from_str(&ip).unwrap(), port) }
    }
}
