import logging
import aniso8601
from datetime import datetime, timezone
from falconpy import Hosts
from .host_rtr import RealTimeResponse


class Detection(object):

    def __init__(self, auth, detect_id) -> None:
        super().__init__()
        self._auth = auth
        self.detect_id = detect_id

    def __str__(self) -> str:
        return f"<Crowdstrike Falcon Detection: {self.detect_id}>"

    def get_summary(self):
        query = {"ids": [self.detect_id]}
        details = self._auth.get_falcon_harness().command("GetDetectSummaries", body=query)
        if details['status_code'] == 200 and len(details['body']['resources']) == 1:
            return details['body']['resources'][0]
        else:
            raise Exception(f'Failed to obtain detect summary for detection ID {self.detect_id}')

    def get_host(self):
        from .host import Host
        summary = self.get_summary()
        if "device" in summary and "device_id" in summary["device"]:
            return Host(auth=self._auth, aid=summary["device"]["device_id"])
        else:
            raise Exception(f'No host defined for detection ID {self.detect_id}')