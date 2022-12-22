import pandas as pd
from falconpy import Hosts
from falconpy import RealTimeResponse as RTR, RealTimeResponseAdmin as RTRAdmin
import logging
import py7zr
import os

from .host import Host


class BulkOperationOutcome(object):

    def __init__(self, auth, client, batch_id, session_id, aid, cloud_request_id=None, error_msg=None, stdout=None,
                 stderr=None, command=None, content=None) -> None:
        super().__init__()
        self._auth = auth
        self.client = client
        self.error = stderr is not None and len(stderr.strip()) > 0
        self.aid = aid
        self.batch_id = batch_id
        self.session_id = session_id
        self.cloud_request_id = cloud_request_id
        self.error_msg = error_msg
        self.stdout = stdout
        self.stderr = stderr
        self.command = command
        self.content = content

    @classmethod
    def from_get_file_success(cls, auth, client, batch_id, session_id, aid, cloud_request_id, content):
        return cls(auth=auth, client=client, batch_id=batch_id, session_id=session_id, aid=aid,
                   cloud_request_id=cloud_request_id, content=content)

    @classmethod
    def from_get_file_error_cloud_request(cls, auth, client, batch_id, session_id, aid, cloud_request_id, error_msg):
        return cls(auth=auth, client=client, batch_id=batch_id, session_id=session_id, aid=aid,
                   cloud_request_id=cloud_request_id, error_msg=error_msg)

    @classmethod
    def from_get_file_error(cls, auth, client, batch_id, session_id, aid, error_msg):
        return cls(auth=auth, client=client, batch_id=batch_id, session_id=session_id, aid=aid, error_msg=error_msg)

    @classmethod
    def from_run_command(cls, auth, client, batch_id, session_id, aid, error_msg, stdout, stderr, command,
                         cloud_request_id):
        return cls(auth=auth, client=client, batch_id=batch_id, session_id=session_id, aid=aid,
                   error_msg=error_msg, stdout=stdout, stderr=stderr, command=command,
                   cloud_request_id=cloud_request_id)

    def get_host(self):
        return Host(auth=self._auth, aid=self.aid)

    def has_content(self):
        return self.content is not None

    def get_content_as_string(self):
        return self.content.decode()

    def write_content_to_file(self, filename):
        with open(filename, "wb") as out_content:
            out_content.write(self.content)

    def append_content_to_file(self, filename, insert_newline=False):
        with open(filename, "ab") as out_content:
            if insert_newline:
                out_content.write("\n".encode())
            out_content.write(self.content)

    def raise_exception(self):
        if self.error and self.error_msg:
            raise Exception(self.error_msg)
        elif self.error and not self.error_msg:
            raise Exception("Error encountered performing bulk operation")
