# pylamecheck

Some code to check nameserver(s) for domain (zone) "lameness".

Very much a work in progress.

## Installation

1. Install dependencies with OS package manager, primarily this is `getdns`.
2. Clone this git repo, and run the `setup.sh`, which initialises a python virtual environment and installs python requirements.

### Detailed steps:

```
yum install getdns openssl
yum install python-virtualenv git
yum install getdns-devel gcc

git clone https://github.com/techdad/pylamecheck.git

./setup.sh

yum remove gcc
```

### Notes:
* OpenSSL *must* be up to date.

