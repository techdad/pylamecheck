# pylamecheck

Some code to check nameserver(s) for domain (zone) "lameness".

Still somewhat a work in progress.

## Installation

### Base App Installation

1. Install dependencies with OS package manager, primarily this is `getdns`.
2. Clone this git repo, and run the `setup.sh`, which initialises a python virtual environment and installs python requirements.

#### Detailed steps:

(Example is for CentOS/RHEL/Fedora/etc. - replace with package manager of choice as desired)

```
yum install getdns openssl
yum install python-virtualenv git
yum install getdns-devel gcc

cd /opt
git clone https://github.com/techdad/pylamecheck.git
cd pylamecheck
./setup.sh

# optional, but recommended:
yum remove gcc
```

#### Notes:
* OpenSSL *must* be up to date.
* For now, there is the assumption of installing under `/opt`.

### Running with Supervisor

```
yum install supervisor

ln -s /opt/pylamecheck/checklame_supervisor.ini /etc/supervisord.d/

systemctl enable supervisord
systemctl start supervisord
```



