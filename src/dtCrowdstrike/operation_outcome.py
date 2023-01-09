import pandas as pd
from falconpy import Hosts
from falconpy import RealTimeResponse as RTR, RealTimeResponseAdmin as RTRAdmin
import logging
import py7zr
import os


class OperationOutcome(object):

    def __init__(self, auth, client) -> None:
        super().__init__()
        self._auth = auth
        self.client = client
        self._response = None
        self._headers = None
        self._status_code = None
        self.success = False
        self._meta = None
        self.error_code = None
        self.error_message = None
        self.multiple_errors = False
        self.resource_id = None
        self.resource_path = None
        self.multiple_resources = False

    @classmethod
    def from_command_response(cls, auth, client, response):
        obj = cls(auth=auth, client=client)
        obj._response = response
        obj._headers = response.get("headers", None)
        obj._status_code = response.get("status_code", -1)
        obj.success = 200 <= obj._status_code < 300

        if "body" in response:
            obj._meta = response.get("body").get("meta", None)

            if "errors" in response.get("body") and len(response.get("body").get("errors", [])) == 1:
                obj.success = False
                obj.error_code = response.get("body").get("errors")[0].get("code", -1)
                obj.error_message = response.get("body").get("errors")[0].get("message", None)
            elif "errors" in response.get("body") and len(response.get("body").get("errors", [])) > 1:
                obj.multiple_errors = True

            if "resources" in response.get("body") and len(response.get("body").get("resources", [])) == 1:
                obj.resource_id = response.get("body").get("resources")[0].get("id", -1)
                obj.resource_path = response.get("body").get("resources")[0].get("path", None)
            elif "resources" in response.get("body") and len(response.get("body").get("resources", [])) > 1:
                obj.multiple_resources = True
        return obj

    def exception(self):
        if not self.success and not self.multiple_errors:
            raise Exception(f'{self.error_message} - ERROR CODE: {self.error_code}')
        elif not self.success and self.multiple_errors:
            raise Exception(f'Multiple errors occurred: {str(self._response.get("body").get("errors", []))}')
