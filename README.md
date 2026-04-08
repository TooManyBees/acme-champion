# acme-champion

Perform a DNS-01 ACME challenge completely locally, so you never need to store credentials for your DNS provider on your server. It consists of 2 parts:

1. `acme-champion`, an extremely minimal DNS server
2. `certbot-dns-champ`, a Certbot plugin which sets DNS challenges on a running `acme-champion` process

# Usage

Basic usage is as follows:

1. Configure your DNS to delegate the subzone `_acme-challenge.yourdomain.tld` to the server that hosts `yourdomain.tld`. Do this for each domain you wish to obtain certificates for.
2. Run `acme-champion` as a background process on your server.
3. Install the `certbot-dns-champ` Python package.
4. When you run any certbot action that prompts a challenge, invoke certbot with `--authenticator dns-champ`.

## Example

A sample script to run Certbot using `acme-champion`, on a system with `ufw` as a firewall, might look like this:

```bash
# start acme-champion as a background process
path/to/acme-champion --dns-addr 0.0.0.0:53 --http-port 8053 &
```

```bash
# run this as a superuser
ufw allow dns && ufw reload
certbot certonly --authenticator dns-champ --dns-champ-http-port 8053
ufw deny dns && ufw reload
```

The options `--http-port` and `--dns-champ-http-port` are both optional and default to 8053, but must match.

## How it works

`acme-champion` relies on being able to delegate your own server at `yourdomain.tld` as the authoritative name server for `_acme-challenge.yourdomain.tld`. Add a similar NS record via your DNS provider:

```
_acme-challenge.yourdomain.tld. 30 IN  NS  yourdomain.tld.
```

Run `acme-champion` on your server. It listens for DNS traffic from the Internet, and HTTP traffic on localhost. It exposes the following HTTP routes:

* `POST /register/{domain}` sets a DNS challenge
  * `domain` is the name of the domain that the certificate will be issued for
  * The required header `X-ACME-Challenge-Name` is the name of the challenge TXT record, usually `domain` with the label `_acme-challenge` prepended to it
  * The required header `X-ACME-Challenge-Value` is the value of the challenge record
* `DELETE /register/{domain}` deletes a previously set challenge
  * The same headers as above are required
* `GET /` is a health check that just returns a `200 Ok` status code

For any registered ACME challenges, `acme-champion` will answer these DNS queries:

* `TXT` answers with each challenge value that corresponds to the challenge name.
* `NS` removes the `_acme-challenge` label from the challenge name to determine the parent domain, and responds with an NS answer that delegates `_acme-challenge.parent.domain` to `parent.domain`. This is intended to match the NS records that you set on each of the domains you wish to obtain certificates for.
* `SOA` returns an arbitrary SOA record.

If `acme-champion` was started with DNS addresses that aren't unspecified (`0.0.0.0` or `[::]`), it will answer `A` or `AAAA` queries with the appropriate IP address.

## Configuration

`acme-champion` is configured through command arguments and/or environment variables. Arguments take precedence.

| Arg name | Env var name | Description |
|----------|--------------|-------------|
| `--http-port` | `CERTBOT_DNS_CHAMP_HTTP_PORT` | The TCP port to listen for the API. Defaults to `8053`. If you change this, you must also invoke the dns-champ authenticator with `--dns-champ-http-port`. The API always listens on the loopback address `127.0.0.1`. |
| `--dns-addr` | `CERTBOT_DNS_CHAMP_DNS_ADDR` `CERTBOT_DNS_CHAMP_DNS_ADDR_6` | The UDP address to listen for DNS traffic, in the form `IP:PORT`. Using args, you can set this twice: once for IPv4, and once for IPv6. Defaults to `127.0.0.1:5053` and `[::1]:5053` in debug, and `0.0.0.0:53` and `[::]:53` in release. |
| `--log-level` | `CERTBOT_DNS_CHAMP_LOG_LEVEL` | Log level. `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. Defaults to `INFO` |
| `--log-format` | `CERTBOT_DNS_CHAMP_LOG_FORMAT` | Log format. `plain`, `pretty`, `journald` (only when compiled with the `journald` feature). Defaults to `pretty` in debug, and `plain` in release. |

# Safety as an exposed DNS server

`acme-champion` is a stub DNS server. It does not recurse to any other name servers, and only answers challenges for names that begin with the label `_acme-challenge`. If left exposed to the internet, it can't do any harm to your server or others' DNS servers.
