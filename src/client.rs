extern crate pcap;
extern crate hyper;
extern crate rustc_serialize;
use pcap::{Device, Capture};
use std::sync::mpsc::{channel, Sender, Receiver};
use pingnet::{PingPacket, PacketContainer};
use std::thread;
use hyper::Client;
use std::collections::VecDeque;
use rustc_serialize::{json, Encodable};
use Runnable;

pub struct CaptureClient {
    post_url: String,
    buffer_size: u32,
    bpf_filter: String,
    identifier: String,
    sender: Option<Sender<Option<PingPacket>>>,
    capture_thread: Option<thread::JoinHandle<()>>,
    transmit_thread: Option<thread::JoinHandle<()>>,
}


impl Runnable for CaptureClient {
    fn exit(&mut self) {
        self.sender
            .clone()
            .unwrap()
            .send(None)
            .expect("Could not send poison pill to transmit thread");
        let transmit_thread = self.transmit_thread.take().unwrap();
        transmit_thread.join().expect("Could not exit gracefully");
    }
    fn start(&mut self) {
        let (tx, rx) = channel();
        self.sender = Some(tx.clone());
        self.capture_thread = Some(Self::start_capture(tx, self.prepare_capture()));
        self.transmit_thread = Some(Self::start_transmit(rx,
                                                         self.post_url.clone(),
                                                         self.buffer_size as usize,
                                                         self.identifier.clone()));
    }
}

impl CaptureClient {
    pub fn new(post_url: String, buffer_size: u32, identifier: String) -> CaptureClient {
        CaptureClient {
            post_url: post_url,
            buffer_size: buffer_size,
            identifier: identifier,
            bpf_filter: String::from("icmp[icmptype] == icmp-echoreply"),
            sender: None,
            capture_thread: None,
            transmit_thread: None,
        }
    }

    fn start_capture<'a>(tx: Sender<Option<PingPacket>>,
                         mut cap: Capture<pcap::Active>)
                         -> thread::JoinHandle<()> {
        let t_capture = thread::spawn(move || {
            debug!("[t_capture] Capture thread started");
            while let Ok(packet) = cap.next() {
                debug!("[t_capture] Packet received");
                let pp = PingPacket::from(packet);
                tx.send(Some(pp)).unwrap();
            }
        });
        t_capture
    }

    fn start_transmit(rx: Receiver<Option<PingPacket>>,
                      post_url: String,
                      buffer_size: usize,
                      identifier: String)
                      -> thread::JoinHandle<()> {
        let t_transmit = thread::spawn(move || {
            debug!("[t_transmit] Transmit thread started");
            let mut buf = VecDeque::new();
            loop {
                debug!("[t_capture] Transmitting data");
                let data = rx.recv().unwrap();

                if let Some(data) = data {
                    buf.push_back(data);

                    if buf.len() >= buffer_size {
                        let result = Self::http_send_packets(&mut buf, &post_url, &identifier);
                        if result.is_err() {
                            println!("Failed to transmit data. (Retry will occur)");
                        }
                    }
                } else {
                    Self::http_send_packets(&mut buf, &post_url, &identifier)
                        .expect("Unable to send final batch of packets");
                    break;
                }
            }
        });
        t_transmit
    }

    fn http_send_packets<T: Encodable>(buffer: &mut VecDeque<T>,
                                       post_url: &str,
                                       identifier: &str)
                                       -> Result<hyper::client::Response, hyper::Error> {
        // Initialize Hyper client
        let client = Client::new();

        // Take data from the queue
        let collected_packets = buffer.drain(..).collect::<Vec<T>>();

        // Serialize
        let ppc = PacketContainer {
            host_identifier: identifier.to_string(),
            data: collected_packets,
        };
        let encoded_packets = json::encode(&ppc).unwrap();

        // Post
        let result = client.post(post_url)
                           .body(&encoded_packets)
                           .send();

        // In case of an error push data back on to the queue
        if result.is_err() {
            for item in ppc.data {
                buffer.push_back(item);
            }
        }
        result
    }

    fn prepare_capture(&self) -> Capture<pcap::Active> {
        let main_device = Device::lookup().unwrap();
        let mut cap: Capture<pcap::Active> = Capture::from_device(main_device)
                                                 .unwrap()
                                                 .promisc(true)
                                                 .snaplen(5000)
                                                 .open()
                                                 .unwrap();
        cap.filter(&self.bpf_filter).unwrap();
        cap
    }
}
