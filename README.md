# packetcapr 
[![Build Status](https://travis-ci.org/Woutifier/packetcapr.svg?branch=master)](https://travis-ci.org/Woutifier/packetcapr)
## Dependencies
- Rust
- Libpcap

## Build
```
cargo build --release
```

## Binaries
Statically compiled binaries for x86_64 are provided. See: https://github.com/Woutifier/packetcapr/releases

## Commandline options
```Usage:
    ./packetcapr [OPTIONS]

Captures packets and sends them, in batches, to a specified URL using HTTP

optional arguments:
  -h,--help             show this help message and exit
  -v,--verbose          Be verbose
  -s,--server-mode      Start in server mode (default: client mode)
  -u,--url URL          URL to send packets to (default: http://localhost:1338)
  -b,--batchsize BATCHSIZE
                        Size of each batch (default: 10)
  -i,--hostidentifier HOSTIDENTIFIER
                        Identifier that will be added to each request (default:
                        default)
  -p,--port PORT        Port to listen on in server mode (default: 1338)
  ```

