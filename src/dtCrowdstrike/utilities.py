import pandas as pd
from .bulk_host_operations import BulkHostOperations
from .bulk_exporters import BulkExporter
from falconpy import Hosts
import logging


class Utilities(object):

    def __init__(self, auth, client) -> None:
        super().__init__()
        self._auth = auth
        self.client = client

    def __hosts(self):
        return Hosts(auth_object=self._auth.get_falcon_auth())

    def bulk_host_operations(self, hosts):
        return BulkHostOperations(auth=self._auth, client=self.client, hosts=hosts)

    def bulk_exporter(self):
        return BulkExporter(auth=self._auth, client=self.client)

    def count(self, hosts):
        i = 0
        for host in hosts():
            i += 1

        return i
