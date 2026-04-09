# acme-champion

Perform a DNS-01 ACME challenge completely locally, so you never need to store credentials for your DNS provider on your server. It consists of 2 parts:

1. `acme-champion`, an extremely minimal DNS server
2. `certbot-dns-champ`, a Certbot plugin which sets DNS challenges on a running `acme-champion` process

# Usage

Basic usage is as follows:

1. For each domain `yourdomain.tld` that your server handles, add a NS record that delegates `_acme-challenge.yourdomain.tld` to `yourdomain.tld` itself.
2. On your server, install the `certbot-dns-champ` Python package, and install `acme-champion`. *(See Installation below)*
3. When you run certbot, first start `acme-champion`, then invoke certbot with `--authenticator dns-champ`.

## Example

You could choose to keep `acme-champion` running all the time in the background. You could also start it on-demand before each certbot invocation, and stop it afterward.

My server uses the firewall `ufw`, so this is a minimal example that works for me.

```sh
# as a background process
acme-champion --dns-addr "$(hostname -I)"

# startup.sh
ufw allow dns && ufw reload

# teardown.sh
ufw deny dns && ufw reload

# certbot.sh
certbot certonly -d mydomain.tld -d *.mydomain.tld \
    --authenticator dns-champ --dns-champ-script-before startup.sh \
    --dns-champ-script-after teardown.sh
```

An example where I only run `acme-champion` on demand could look like this:

```sh
acme-champion --dns-addr "$(hostname -I)"
ACME_CHAMPION_PID=$!

trap "kill $ACME_CHAMPION_PID" EXIT

# 100ms is enough time to know whether or not the process bound its
# listeners, or if it exited with an error
sleep 0.1
if ! ps "$ACME_CHAMPION_PID" > /dev/null; then
  exit 1
fi

if ! ufw allow dns && ufw reload; then
  exit 1
fi

certbot certonly -d mydomain.tld -d *.mydomain.tld \
    --authenticator dns-champ

ufw deny dns && ufw reload
```

## Installation

To install `acme-champion`, `cargo build --release` and copy it to somewhere memorable. `/usr/local/bin` perhaps?

To install the Certbot plugin `dns-champ`, activate the venv associated with Certbot (perhaps `/opt/certbot`, as described in [Certbot's pip installation instructions](https://certbot.eff.org/instructions?ws=other&os=pip)) and `pip install /path/to/acme-champion/certbot-dns-champ`.

Run `certbot plugins` to confirm that `dns-champ` is installed as an authenticator.

## Configuration

`acme-champion` is configured through command arguments and/or environment variables. Arguments take precedence.

| Arg name | Env var name | Description |
|----------|--------------|-------------|
| `--http-port` | `CERTBOT_DNS_CHAMP_HTTP_PORT` | The TCP port to listen for the API. Defaults to `8053`. If you change this, you must also invoke the dns-champ authenticator with `--dns-champ-http-port`. The API always listens on the loopback address `127.0.0.1`. |
| `--dns-addr` | `CERTBOT_DNS_CHAMP_DNS_ADDR` `CERTBOT_DNS_CHAMP_DNS_ADDR_6` | The UDP address(es) to listen for DNS traffic. Can be one or more IP addresses or socket addresses (which include the port number) separated by spaces. Designed so you can dump the output of `hostnames -I` into it, and it will ignore private IPs. Defaults to `127.0.0.1:5053` and `[::1]:5053` in debug, and `0.0.0.0:53` and `[::]:53` in release. |
| `--log-level` | `CERTBOT_DNS_CHAMP_LOG_LEVEL` | Log level. `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`. Defaults to `INFO` |
| `--log-format` | `CERTBOT_DNS_CHAMP_LOG_FORMAT` | Log format. `plain`, `pretty`, `journald` (only when compiled with the `journald` feature). Defaults to `pretty` in debug, and `plain` in release. |

## How it works

`acme-champion` relies on being able to delegate your own server at `yourdomain.tld` as the authoritative name server for `_acme-challenge.yourdomain.tld`. Add a NS record to your DNS provider, similar to this one:

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

# Safety notes

`acme-champion` is a stub DNS server, and:

* does not recurse to any other name servers
* only references its own internal storage for DNS answers
* stores a maximum of 100 challenges before erasing the oldest ones
* only processes queries for names that begin with the label `_acme-challenge`
* is practically incapable of returning large responses, or handling requests with high concurrency, making it not a very useful pawn in a DNS amplification attack

I recommend you keep port 53 firewalled when you're not actively renewing certificates, but `acme-champion` is still designed to be a good neighbor to both the internet and your server.
