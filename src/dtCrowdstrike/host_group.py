import logging
import aniso8601
from datetime import datetime, timezone
from falconpy import Hosts
from .host_rtr import RealTimeResponse
from .host import Host


class HostGroup(object):

    def __init__(self, auth, group_id, client) -> None:
        super().__init__()
        self._auth = auth
        self.group_id = group_id
        self.client = client
        self.__group_details = None
        self.__group_details_last_collected = None
        self.__group_deleted = False

    def __str__(self) -> str:
        return f"<Crowdstrike Falcon Host Group: {self.group_id}>"

    def __read_details(self):
        response = self._auth.get_falcon_harness().command("getHostGroups", ids=[self.group_id])
        if response['status_code'] == 200 and len(response['body']['resources']) == 1:
            return response['body']['resources'][0]
        else:
            raise Exception(f'Failed to read Group Details for Group ID {self.group_id} -> ({response})')

    def __get_updated_details(self, force=False):
        if not self.__group_details:
            self.__group_details = self.__read_details()
            self.__group_details_last_collected = datetime.now()

        if (datetime.now() - self.__group_details_last_collected).seconds > 600:
            self.__group_details = self.__read_details()
            self.__group_details_last_collected = datetime.now()

        if force or self.__group_deleted:
            self.__group_details = self.__read_details()
            self.__group_details_last_collected = datetime.now()

        return self.__group_details

    def count_hosts(self):
        return self.client.get_utilities().count(self.get_hosts)

    def get_hosts(self):
        offset = 0
        while True:
            resp = self._auth.get_falcon_harness().command("queryGroupMembers",
                                                           id=self.group_id,
                                                           offset=offset,
                                                           limit=100
                                                           )
            if resp['status_code'] == 200:
                if len(resp['body']['resources']) == 0:
                    break
                else:
                    for aid in resp['body']['resources']:
                        yield Host(auth=self._auth, aid=aid)
                    offset += 100
            else:
                raise Exception(f'Failed to find hosts for group ID {self.group_id}')

    def get_details(self):
        return self.__get_updated_details()

    def get_name(self):
        return self.__get_updated_details()['name']

    def get_description(self):
        return self.__get_updated_details()['description']

    def add_host(self, host):
        return self.add_hosts([host])

    def add_hosts(self, hosts):
        host_ids = []
        for host in hosts:
            host_ids.append(host.aid)

        req_body = {
            "action_parameters": [
                {
                    "name": "filter",
                    "value": f"(device_id:{str(host_ids)})"
                }
            ],
            "ids": [self.group_id]
        }
        response = self._auth.get_falcon_harness().command("performGroupAction", action_name="add-hosts", body=req_body)

        if response['status_code'] == 200:
            return {"complete": True, "success": True, "operation": "add-hosts"}
        else:
            return {"complete": True, "success": False, "response": response, "operation": "add-hosts"}

    def add_hosts_by_filter(self, filter_query):
        req_body = {
            "action_parameters": [
                {
                    "name": "filter",
                    "value": filter_query
                }
            ],
            "ids": [self.group_id]
        }
        response = self._auth.get_falcon_harness().command("performGroupAction", action_name="add-hosts", body=req_body)

        if response['status_code'] <= 201:
            return {"complete": True, "success": True, "operation": "add-hosts", "filter_query": filter_query}
        else:
            return {"complete": True, "success": False, "response": response, "operation": "add-hosts",
                    "filter_query": filter_query}

    def remove_host(self, host):
        return self.remove_hosts([host])

    def remove_hosts(self, hosts):
        host_ids = []
        for host in hosts:
            host_ids.append(host.aid)

        req_body = {
            "action_parameters": [
                {
                    "name": "filter",
                    "value": f"(device_id:[{','.join(host_ids)}])"
                }
            ],
            "ids": [self.group_id]
        }
        response = self._auth.get_falcon_harness().command("performGroupAction", action_name="remove-hosts", body=req_body)

        if response['status_code'] <= 201:
            return {"complete": True, "success": True, "operation": "remove-hosts"}
        else:
            return {"complete": True, "success": False, "response": response, "operation": "remove-hosts"}

    def set_name(self, name):
        req_body = {
            "resources": [
                {
                    "id": self.group_id,
                    "name": name
                }
            ]
        }

        response = self._auth.get_falcon_harness().command("updateHostGroups", body=req_body)

        if response['status_code'] <= 201:
            self.__get_updated_details(force=True)
            return {"complete": True, "success": True, "operation": "set-name", "value": name}
        else:
            return {"complete": True, "success": False, "response": response, "operation": "set-name", "value": name}

    def set_description(self, description):
        req_body = {
            "resources": [
                {
                    "id": self.group_id,
                    "description": description
                }
            ]
        }

        response = self._auth.get_falcon_harness().command("updateHostGroups", body=req_body)

        if response['status_code'] <= 201:
            self.__get_updated_details(force=True)
            return {"complete": True, "success": True, "operation": "set-description", "value": description}
        else:
            return {"complete": True, "success": False, "response": response, "operation": "set-description",
                    "value": description}

    def delete(self):
        response = self._auth.get_falcon_harness().command("deleteHostGroups", ids=[self.group_id])
        if response['status_code'] <= 201:
            self.__group_deleted = True
            return {"complete": True, "success": True, "operation": "delete-group", "value": None}
        else:
            return {"complete": True, "success": False, "response": response, "operation": "delete-group",
                    "value": None}
