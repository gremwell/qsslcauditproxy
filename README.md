# qsslcauditproxy

Qsslcauditproxy is a proxy wrapper for the qsslcaudit tool, which is available at [https://github.com/gremwell/qsslcaudit](https://github.com/gremwell/qsslcaudit).

The script will then act as a non-intercepting proxy for all SSL traffic. For each new host, it will redirect the SSL stream to an instance of qsslcaudit, so that the client connection can be tested. HTTP connections will just be forwarded, so nothing is blocked.

When a host is tested, the original flow is restored so that the application functionality can go back to normal.
The script can also be configured with a blacklist file. If a part of the hostname matches a blacklist entry, this host will not be tested. 

## Installation

Simply clone the repository:

```
git clone https://github.com/gremwell/qsslcauditproxy
cd qsslcauditproxy
```

### Requirements

You need to install qsslcaudit on your system first. To do so, follow the instructions at [https://github.com/gremwell/qsslcaudit](https://github.com/gremwell/qsslcaudit).
Other than that, the application is self-contained and does not depend on external libraries. The only requirement is Python version 3.

## Usage

The proxy can be launched using Python3:

```
python3 qsslcauditproxy.py -h

=====================================
        Qsslcauditproxy v0.0.1
  Sean de Regge (sean@gremwell.com)
=====================================

usage: qsslcauditproxy.py [-h] [--blacklist BLACKLIST] [-p P]

A proxy wrapper for Qsslcaudit (https://github.com/gremwell/qsslcaudit)

optional arguments:
  -h, --help            show this help message and exit
  --blacklist BLACKLIST
                        Blacklist file that holds hosts to exclude from
                        testing, for example known endpoints used by the OS
                        (default: None)
  --whitelist WHITELIST
                        Whitelist file. Only test the hosts listed in the file.
                        --whitelist and --blacklist can't be used together.
  -p P                  Port for proxy to listen on (default: 8888)
```

