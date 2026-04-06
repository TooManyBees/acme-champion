from certbot import achallenges, errors
from certbot.plugins import dns_common
import http.client, urllib.parse
import logging
import shlex, subprocess
from typing import Callable

logger = logging.getLogger(__name__)

class Authenticator(dns_common.DNSAuthenticator):
    description = "Obtain certificates using a minimal DNS server running " + \
                  "on the same host as Certbot."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.pid = None

    def more_info():
        return "This plugin answers ACME challenges by running a minimal" + \
               "DNS server on this machine."

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add("http-port", default=8053, help='Port on which acme-champion listens for HTTP traffic')

    def auth_hint(self, failed_achalls: list[achallenges.AnnotatedChallenge]) -> str:
        """See certbot.plugins.common.Plugin.auth_hint."""
        return (
            'The Certificate Authority failed to verify the DNS TXT records created by --{name}. '
            'Ensure that you are delegating the _acme-challenge DNS sub-zone to '
            "this machine's address, and that port 53 traffic is not being blocked."
            .format(name=self.name)
        )

    def _setup_credentials(self) -> None:
        return None

    def _perform(self, domain: str, validation_name: str,
                 validation: str) -> None:
        try:
            conn = http.client.HTTPConnection("localhost", self.conf('http-port'), timeout=5)
            conn.request("POST", "/register/{}".format(domain), headers={"X-ACME-Challenge-Name": validation_name, "X-ACME-Challenge-Value": validation})
            response = conn.getresponse()
        except http.client.HTTPException as err:
            raise errors.PluginError("Could not reach acme-champion on localhost: {}".format(err))
        finally:
            conn.close()
        if response.status != 201:
            raise errors.PluginError("Unexpected HTTP status setting challenge: {}".format(response.status))

    def _cleanup(self, domain: str, validation_name: str,
                 validation: str) -> None:
        try:
            conn = http.client.HTTPConnection("localhost", self.conf('http-port'), timeout=5)
            conn.request("DELETE", "/register/{}".format(domain), headers={"X-ACME-Challenge-Name": validation_name, "X-ACME-Challenge-Value": validation})
            response = conn.getresponse()
        except http.client.HTTPException as err:
            logger.warning("Could not reach acme-champion on localhost: %s", err)
            return # who cares
        finally:
            conn.close()
        if response.status != 204:
            logger.warning("unexpected status code cleaning up %s: %d", validation_name, response.status)

