import logging
import aniso8601
from datetime import datetime, timezone
from falconpy import Hosts
from .host_rtr import RealTimeResponse
from .detect import Detection
from .operation_outcome import OperationOutcome


class Host(object):

    def __init__(self, auth, aid) -> None:
        super().__init__()
        self._auth = auth
        self.aid = aid
        self.__host_details = None
        self.__host_details_last_collected = None

    def __str__(self) -> str:
        return f"<Crowdstrike Falcon Host: {self.aid}>"

    def __read_details(self):
        try:
            details = self.__hosts().get_device_details(ids=[self.aid])
            if 'resources' in details['body'] and len(details['body']['resources']) == 1:
                return details['body']['resources'][0]
            else:
                raise Exception(f'Failed to read host details. {str(details)}')
        except Exception as ex:
            logging.exception(f'Failed to read host details. {str(ex)}')
            raise ex

    def __get_updated_details(self, force=False):
        if not self.__host_details:
            self.__host_details = self.__read_details()
            self.__host_details_last_collected = datetime.now()

        if (datetime.now() - self.__host_details_last_collected).seconds > 600:
            self.__host_details = self.__read_details()
            self.__host_details_last_collected = datetime.now()

        if force:
            self.__host_details = self.__read_details()
            self.__host_details_last_collected = datetime.now()

        return self.__host_details

    def __hosts(self):
        return Hosts(auth_object=self._auth.get_falcon_auth())

    def get_host_status(self):
        self.__get_updated_details(force=True)
        return self.get_host_details()['status']

    def get_host_details(self):
        return self.__get_updated_details()

    def get_summary_host_details(self):
        try:
            details = self.get_host_details()
            return {"resource": self.aid, 'hostname': details['hostname'],
                    'os_version': details.get('os_version', None),
                    'os_build': details.get('os_build', None)}

        except Exception as ex:
            logging.exception(f'Failed to read host details. {str(ex)}')
            raise ex

    def seen_in_last(self, days):
        return (datetime.now(timezone.utc) - self.last_seen()).days <= days

    def last_seen(self):
        return aniso8601.parse_datetime(self.get_host_details()['last_seen'])

    def first_seen(self):
        return aniso8601.parse_datetime(self.get_host_details()['first_seen'])

    def get_realtime_response(self):
        return RealTimeResponse(auth=self._auth, aid=self.aid, host=self)

    def get_hostname(self):
        return self.get_host_details()['hostname']

    def is_windows(self):
        return self.get_host_details()['platform_name'] == "Windows"

    def is_linux(self):
        return self.get_host_details()['platform_name'] == "Linux"

    def is_mac(self):
        return self.get_host_details()['platform_name'] == "Mac"

    def get_detections(self, limit=5000):
        detects = self._auth.get_falcon_harness().command("QueryDetects", limit=limit,
                                                          filter=f"device.device_id:'{self.aid}'")
        if detects['status_code'] == 200:
            for id in detects['body']['resources']:
                yield Detection(auth=self._auth, detect_id=id)
        else:
            raise Exception(f'Failed to read detections ({str(detects)})')

    def isolate(self):
        req_body = {
            "ids": [self.aid]
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="contain", body=req_body)
        return OperationOutcome.from_command_response(client=None, auth=self._auth, response=response)

    def lift_isolation(self):
        req_body = {
            "ids": [self.aid]
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="lift_containment", body=req_body)
        return OperationOutcome.from_command_response(client=None, auth=self._auth, response=response)

    def hide_host(self):
        req_body = {
            "ids": [self.aid]
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="hide_host", body=req_body)
        return OperationOutcome.from_command_response(client=None, auth=self._auth, response=response)

    def unhide_host(self):
        req_body = {
            "ids": [self.aid]
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="unhide_host", body=req_body)
        return OperationOutcome.from_command_response(client=None, auth=self._auth, response=response)

    def suppress_detections(self):
        req_body = {
            "ids": [self.aid]
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="detection_suppress", body=req_body)
        return OperationOutcome.from_command_response(client=None, auth=self._auth, response=response)

    def unsuppress_detections(self):
        req_body = {
            "ids": [self.aid]
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="detection_unsuppress", body=req_body)
        return OperationOutcome.from_command_response(client=None, auth=self._auth, response=response)