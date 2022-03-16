import os
import logging
import requests
import urllib3
import socket

class API():
    url = None
    verify = None


    @staticmethod
    def ipv4_only():
        return socket.AF_INET


    def __init__(self, url="http://localhost", verify_ssl=True, ipv4_only=False):
        self.url = url
        self.verify = verify_ssl
        
        if ipv4_only:
            import urllib3.util.connection as urllib3_connection

            urllib3_connection.allowed_gai_family = self.ipv4_only

        if not self.verify:
            urllib3.disable_warnings()


    def api(self, uri, method='GET', **kwargs):
        logging.debug(f"{method} {self.url}/{uri}...")

        r = requests.request(
            url=f"{self.url}/{uri}",
            method=method,
            verify=self.verify,
            **kwargs,
        )

        logging.debug("API RC: {}".format(r.status_code))

        return r.status_code, r.json() if r.text else None
