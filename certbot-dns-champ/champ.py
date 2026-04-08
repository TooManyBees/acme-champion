from acme import challenges
from certbot import achallenges, errors
from certbot.plugins import dns_common
import http.client
import logging
import subprocess
import shlex, subprocess
from time import sleep
from typing import Callable

logger = logging.getLogger(__name__)

class Authenticator(dns_common.DNSAuthenticator):
    description = "Obtain certificates using a minimal DNS server running " + \
                  "on the same host as Certbot."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.child_process = None

    def more_info():
        return "This plugin answers ACME challenges by running a minimal" + \
               "DNS server on this machine."

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, 1)
        add("http-port", default=8053, help='Port on which acme-champion listens for HTTP traffic')
        add("script-before", help="Path to a shell script to run before performing authentication")
        add("script-after", help="Path to a shell script to run after performing authentication")
        add("executable", help="Path to acme-champion")

    def auth_hint(self, failed_achalls: list[achallenges.AnnotatedChallenge]) -> str:
        """See certbot.plugins.common.Plugin.auth_hint."""
        return (
            'The Certificate Authority failed to verify the DNS TXT records created by --{name}. '
            'Ensure that you are delegating the _acme-challenge DNS sub-zone to '
            "this machine's address, and that port 53 traffic is not being blocked."
            .format(name=self.name)
        )

    def _setup_credentials(self) -> None:
        pass

    def perform(self, *args, **kwargs) -> list[challenges.ChallengeResponse]:
        self._run_setup_script()
        self._run_acme_champion()
        return super().perform(*args, **kwargs)

    def _perform(self, domain: str, validation_name: str,
                 validation: str) -> None:
        try:
            conn = http.client.HTTPConnection("localhost", self.conf('http-port'), timeout=5)
            conn.request("POST", "/register/{}".format(domain), headers={"X-ACME-Challenge-Name": validation_name, "X-ACME-Challenge-Value": validation})
            response = conn.getresponse()
        except (http.client.HTTPException, ConnectionError) as err:
            raise errors.PluginError("Could not reach acme-champion on localhost: {}".format(err))
        finally:
            conn.close()
        if response.status != 201:
            raise errors.PluginError("Unexpected HTTP status setting challenge: {}".format(response.status))

    def cleanup(self, *args, **kwargs) -> None:
        result = super().cleanup(*args, **kwargs)
        self._stop_acme_champion()
        self._run_teardown_script()
        result

    def _cleanup(self, domain: str, validation_name: str,
                 validation: str) -> None:
        try:
            conn = http.client.HTTPConnection("localhost", self.conf('http-port'), timeout=5)
            conn.request("DELETE", "/register/{}".format(domain), headers={"X-ACME-Challenge-Name": validation_name, "X-ACME-Challenge-Value": validation})
            response = conn.getresponse()
        except (http.client.HTTPException, ConnectionError) as err:
            logger.warning("Could not reach acme-champion on localhost: %s", err)
            return
        finally:
            conn.close()
        if response.status != 204:
            logger.warning("unexpected status code cleaning up %s: %d", validation_name, response.status)

    def _run_acme_champion(self) -> None:
        if self.conf("executable") is not None:
            self.child_process = subprocess.Popen(
                [ self.conf("executable"), "--http-port", str(self.conf("http-port")) ],
                stdout=subprocess.PIPE,
                text=True
            )
            sleep(0.1)
            self.child_process.poll()
            if self.child_process.returncode is not None:
                # TODO add error handling here
                # the process exited early
                pass

    def _stop_acme_champion(self) -> None:
        if self.child_process is not None:
            self.child_process.kill()

    def _run_setup_script(self) -> None:
        if self.conf("script-before") is not None:
            try:
                subprocess.run(
                    [ self.conf("script-before") ],
                    capture_output=True,
                    text=True,
                    check=True
                )
            except subprocess.CalledProcessError as err:
                raise errors.PluginError("startup script exited with nonzero status: %d\n%s\n%s\n", err.returncode, err.stdout, err.stderr)

    def _run_teardown_script(self) -> None:
        if self.conf("script-after") is not None:
            try:
                subprocess.run(
                    [ self.conf("script-after") ],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except subprocess.CalledProcessError as err:
                logger.warning("teardown script exited with nonzero status: %d\n%s\n%s\n", err.returncode, err.stdout, err.stderr)
