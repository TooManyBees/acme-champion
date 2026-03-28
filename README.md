# acme-champion

Perform a DNS-01 ACME challenge completely locally, so you never need to store credentials for your DNS provider on your server. It consists of 2 parts:

1. `acme-champion`, an extremely minimal DNS server which only responds to ACME challenge requests, and exposes a HTTP API for setting challenges
2. `certbot-champ`, a Certbot plugin which interacts with a running `acme-champion` process via its HTTP API to set and clear challenges

# Usage

Basic usage is as follows:

1. Run `acme-champion` as a background process on your server
2. Configure your DNS to delegate the subzone `_acme-challenge.yourdomain.tld` to the server that hosts `yourdomain.tld`.
3. Install `certbot-acme-champion`
4. When you run any certbot action that prompts a challenge, invoke certbot with `--acme-champion`

## Example

A sample script to run Certbot using `acme-champion`, on a system with `ufw` as a firewall, might look like this:

```bash
# start acme-champion in the background
path/to/acme-champion --dns-addr 0.0.0.0:53 --http-port 8053 &
```

```bash
# 
ufw allow dns && ufw reload
sudo certbot certonly --acme-champion --http-port 8053
ufw deny dns && ufw reload
```

The HTTP port defaults to 8053 for both the executable and the Certbot plugin; just note that they have to be the same.

## Configuration

`acme-champion` is configured through command arguments and/or environment variables. Arguments take precedence.

| Arg name | Env var name | Description |
|----------|--------------|-------------|
| `--http-port` | `CHAMP_HTTP_PORT` | The TCP port to listen for the API. Defaults to `8053`. The API always listens on the loopback interface `127.0.0.1`. |
| `--dns-addr` | `CHAMP_DNS_ADDR` `CHAMP_DNS_ADDR_6` | The UDP address to listen for DNS traffic, in the form `IP:PORT`. The argument value can be either an IPv4 or IPv6 address; just set it twice to listen on both. Defaults to `0.0.0.0:5053` in debug, and `0.0.0.0:53` in release. |
| `--level` | `CHAMP_LOG_LEVEL` | Log level. `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. Defaults to `INFO` |

# Safety as an exposed DNS server

`acme-champion` is a stub DNS server. It does not recurse to any other name servers, and only answers challenges for names that begin with the label `_acme-challenge`. If left exposed to the internet, it can't do any harm to your server or others' DNS servers.
