import logging

from ._auth import _Auth
from .host import Host
from .detect import Detection
from .host_group import HostGroup
from .utilities import Utilities
from falconpy import Hosts


class CrowdstrikeClient(object):

    def __init__(self, client_secret, client_id) -> None:
        super().__init__()
        self._auth = _Auth(client_secret=client_secret, client_id=client_id)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self._auth.close()

    def get_host_groups(self):
        offset = 0
        while True:
            response = self._auth.get_falcon_harness().command("queryHostGroups", limit=10, offset=offset)
            if response['status_code'] == 200:
                if len(response['body']['resources']) == 0:
                    break
                else:
                    for group_id in response['body']['resources']:
                        yield HostGroup(auth=self._auth, group_id=group_id, client=self)
                    offset = response['body']['meta']['pagination']['offset']
            else:
                raise Exception(f'Failed to read Host Groups: {str(response)}')

    def create_static_host_group(self, name, description):
        req_body = {
            "resources": [
                {
                    "description": description,
                    "group_type": "static",
                    "name": name
                }
            ]
        }

        response = self._auth.get_falcon_harness().command("createHostGroups", body=req_body)
        if response['status_code'] == 201 and response['body']['errors'] is None and len(response['body']['resources']) == 1:
            return HostGroup(auth=self._auth, client=self, group_id=response['body']['resources'][0]['id'])
        else:
            raise Exception(str(response['body']['errors']))

    def create_dynamic_host_group(self, name, description, rule):
        req_body = {
            "resources": [
                {
                    "assignment_rule": rule,
                    "description": description,
                    "group_type": "dynamic",
                    "name": name
                }
            ]
        }

        response = self._auth.get_falcon_harness().command("createHostGroups", body=req_body)
        if response['status_code'] == 201 and response['body']['errors'] is None and len(response['body']['resources']) == 1:
            return HostGroup(auth=self._auth, client=self, group_id=response['body']['resources'][0]['id'])
        else:
            raise Exception(str(response['body']['errors']))

    def get_detections(self):
        offset = 0
        while True:
            detects = self._auth.get_falcon_harness().command("QueryDetects", limit=10, offset=offset)
            if detects['status_code'] == 200:
                if len(detects['body']['resources']) == 0:
                    break
                else:
                    for detect_id in detects['body']['resources']:
                        yield Detection(auth=self._auth, detect_id=detect_id)
                    offset += 10
            else:
                raise Exception(f'Failed to read detections ({str(detects)})')

    def count_hosts(self, query):
        self.get_utilities().count(self.find_hosts(query))

    def get_host_by_id(self, aid):
        return Host(auth=self._auth, aid=aid)

    def find_hosts(self, query):
        hosts = Hosts(auth_object=self._auth.get_falcon_auth())
        offset = None
        while True:
            aids = hosts.query_devices_by_filter_scroll(filter=query, limit=100, offset=offset)
            if aids['status_code'] == 200:
                if len(aids['body']['resources']) == 0:
                    break
                else:
                    for aid in aids['body']['resources']:
                        yield Host(auth=self._auth, aid=aid)
                    offset = aids['body']['meta']['pagination']['offset']
                    _filter = None
            else:
                raise Exception(f'Failed to find hosts with query {query}')

    def get_online_windows_servers(self):
        _filter = "(last_seen:>='now-24h' + last_seen:<'now') + platform_name:'Windows' + product_type_desc:'Server'"
        for host in self.find_hosts(_filter):
            yield host

    def get_online_servers(self, in_last_hours='24'):
        _filter = f"(last_seen:>='now-{in_last_hours}h' + last_seen:<'now') + product_type_desc:'Server'"
        for host in self.find_hosts(_filter):
            yield host

    def get_hosts_seen_in_last(self, period):
        _filter = f"(last_seen:>='now-{period}' + last_seen:<'now')"
        for host in self.find_hosts(_filter):
            yield host

    def get_windows_hosts(self):
        _filter = "platform_name:'Windows'"
        for host in self.find_hosts(_filter):
            yield host

    def get_linux_hosts(self):
        _filter = "platform_name:'Linux'"
        for host in self.find_hosts(_filter):
            yield host

    def get_host(self, hostname):
        _filter = f"hostname:'{hostname}'"
        hosts = Hosts(auth_object=self._auth.get_falcon_auth())
        aids = hosts.query_devices_by_filter(filter=f"{_filter}", limit=1)
        if 'resources' in aids["body"] and len(aids["body"]["resources"]) == 1:
            return Host(auth=self._auth, aid=aids["body"]["resources"][0])
        else:
            logging.warning(f"No host with the name '{hostname}' found within Crowdstrike")
            return None

    def get_utilities(self):
        return Utilities(auth=self._auth, client=self)
