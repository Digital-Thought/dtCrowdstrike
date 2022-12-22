import pandas as pd
from falconpy import Hosts
from falconpy import RealTimeResponse as RTR, RealTimeResponseAdmin as RTRAdmin
import logging
import py7zr
import os
from ._utils import count

from .bulk_operation_outcome import BulkOperationOutcome


class BulkExporter(object):

    def __init__(self, auth, client) -> None:
        super().__init__()
        self._auth = auth
        self.client = client

    def __hosts(self):
        return Hosts(auth_object=self._auth.get_falcon_auth())

    def __get_batch_host_details(self, hosts):
        ids = []
        if isinstance(hosts, list):
            for entry in hosts:
                ids.append(entry.aid)
        else:
            for entry in hosts():
                ids.append(entry.aid)

        details = self.__hosts().get_device_details(ids=ids, limit=len(ids))
        if 'resources' in details['body'] and len(details['body']['resources']) > 0:
            for resource in details['body']['resources']:
                yield resource
        else:
            raise Exception(f'Failed to read host details. {str(details)}')

    def export_hosts_as_dataframe(self, host_producer, log_progress=False):
        data = {"ou": []}
        processed_count = 0
        cnt = count(host_producer)
        for detail in self.__get_batch_host_details(host_producer):
            processed_keys = []
            for key in detail:
                if isinstance(detail[key], str) or isinstance(detail[key], int) or isinstance(detail[key], bool):
                    if key not in data:
                        data[key] = []
                        if processed_count > 0:
                            for x in range(processed_count):
                                data[key].append(None)

                    processed_keys.append(key)
                    data[key].append(detail[key])

                if key == 'ou':
                    processed_keys.append(key)
                    data[key].append("/".join(detail[key]))

            for key in data:
                if key not in processed_keys:
                    data[key].append(None)

            processed_count += 1
            if log_progress:
                print(f'Exported entry {str(processed_count)} or {str(cnt)}')

        return pd.DataFrame(data)

    def export_hosts_as_csv(self, host_producer, csv_file, log_progress=False):
        try:
            df = self.export_hosts_as_dataframe(host_producer, log_progress=log_progress)
            df.to_csv(csv_file, index=False, header=True)
            return csv_file
        except Exception as ex:
            raise ex

    def export_hosts_as_json(self, host_producer, log_progress=False):
        try:
            df = self.export_hosts_as_dataframe(host_producer, log_progress=log_progress)
            return df.to_json()
        except Exception as ex:
            raise ex

    def export_hosts_as_xml(self, host_producer, log_progress=False):
        try:
            df = self.export_hosts_as_dataframe(host_producer, log_progress=log_progress)
            return df.to_xml
        except Exception as ex:
            raise ex

    def export_hosts_as_html_table(self, host_producer, log_progress=False):
        try:
            df = self.export_hosts_as_dataframe(host_producer, log_progress=log_progress)
            return df.to_html()
        except Exception as ex:
            raise ex

    def export_hosts_as_excel(self, host_producer, excel_file, sheet_name=None, log_progress=False):
        try:
            df = self.export_hosts_as_dataframe(host_producer, log_progress=log_progress)
            if sheet_name:
                df.to_excel(excel_file, sheet_name=sheet_name, index=False)
            else:
                df.to_excel(excel_file, index=False)
            return excel_file
        except Exception as ex:
            raise ex