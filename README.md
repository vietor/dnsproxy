dnsproxy
========

A simple DNS proxy server, runing on multiple platform

## Installation

```bash
$ make && make install
```

## Simple tutorial

```bash
Usage: dnsproxy [options]
  -p <port> or --port=<port>
                       (local bind port, default 53)
  -R <ip> or --remote-addr=<ip>
                       (remote server ip, default 8.8.8.8)
  -P <port> or --remote-port=<port>
                       (remote server port, default 53)
  -T or --remote-tcp
                       (connect remote server in tcp, default no)
  -f <file> or --hosts-file=<file>
                       (user-defined hosts file)
  -h, --help           (print help and exit)
  -v, --version        (print version and exit)
```
