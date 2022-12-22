import pandas as pd
from falconpy import Hosts
from falconpy import RealTimeResponse as RTR, RealTimeResponseAdmin as RTRAdmin
import logging
import py7zr
import os

from .bulk_operation_outcome import BulkOperationOutcome


class BulkHostOperations(object):

    def __init__(self, auth, client, hosts) -> None:
        super().__init__()
        self._auth = auth
        self.client = client
        self.hosts = hosts
        self.batch_id = None
        self.sessions = None
        self.__init_sessions()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        for key in self.sessions:
            self.__rtr().delete_session(session_id=self.sessions[key]['session_id'])

    def __rtr(self):
        return RTR(auth_object=self._auth.get_falcon_auth())

    def __init_sessions(self):
        ids = []
        for host in self.hosts:
            ids.append(host.aid)

        req = {"host_ids": ids}

        response = self._auth.get_falcon_harness().command("BatchInitSessions", body=req)
        if response['status_code'] == 201:
            self.batch_id = response['body']['batch_id']
            self.sessions = response['body']['resources']
        else:
            raise Exception(f'Failed to initialise batch RTR session for {len(self.hosts)} hosts')

    def refresh(self):
        self._auth.get_falcon_harness().command("BatchRefreshSessions", body={"batch_id": self.batch_id})

    def __rtr_admin(self):
        return RTRAdmin(auth_object=self._auth.get_falcon_auth())

    def __wait_for_response(self, cloud_request_id):
        running = True
        stderr = None
        stdout = None
        while running:
            result = self.__rtr_admin().check_admin_command_status(cloud_request_id=cloud_request_id,
                                                                   sequence=0)
            running = not result['body']['resources'][0]['complete']
            if result["status_code"] != 200 and not running:
                for err in result["body"]["errors"]:
                    raise Exception(f"[{err['code']}] {err['message']}\n")

            for execution in result["body"]["resources"]:
                if "stdout" in execution:
                    stdout = execution['stdout']
                if "stderr" in execution:
                    stderr = execution['stderr']

        return {"cloud_request_id": cloud_request_id, "error": stderr is not None and len(stderr) > 0,
                "stdout": stdout, "stderr": stderr}

    def __host_ids(self):
        ids = []
        for host in self.hosts:
            ids.append(host.aid)
        return ids

    def _run_command(self, base_command, command_string):
        outcomes = []
        responses = []
        for key in self.sessions:
            self.refresh()
            resp = self.__rtr_admin().execute_admin_command(base_command=base_command,
                                                            command_string=command_string,
                                                            session_id=self.sessions[key]['session_id'], persist=False)
            resp['aid'] = key
            resp['session_id'] = self.sessions[key]['session_id']
            responses.append(resp)

        for resp in responses:
            outcome = {}
            if "resources" in resp['body'] and len(resp['body']['resources']) > 0:
                for response in resp['body']['resources']:
                    outcome = self.__wait_for_response(response['cloud_request_id'])

            else:
                outcome['exception'] = f"Failed to run base_command '{base_command}' ({str(resp)})"

            outcomes.append(BulkOperationOutcome.from_run_command(auth=self._auth, client=self.client,
                                                                  batch_id=self.batch_id, command=command_string,
                                                                  cloud_request_id=outcome['cloud_request_id'],
                                                                  stdout=outcome['stdout'],
                                                                  stderr=outcome['stdout'],
                                                                  session_id=resp['session_id'],
                                                                  aid=resp['aid'],
                                                                  error_msg=outcome.get("exception", None)))
        return outcomes

    def file_exists(self, file_absolute_path):
        exists = False
        for outcome in self._run_command(base_command="ls", command_string=f'ls "{file_absolute_path}"'):
            exists = exists and not outcome['error']
        return exists

    def run_command(self, command, parameters=None, timeout=None, encapsulate="```"):
        self.refresh()
        command_string = f"{command}"
        if parameters and encapsulate not in parameters:
            command_string = f"{command} {encapsulate}{parameters}{encapsulate}"
        elif parameters and encapsulate in parameters:
            command_string = f"{command} {parameters}"
        if timeout:
            command_string = f"{command_string} -Timeout={str(timeout)}"

        response = self._run_command(base_command=command, command_string=command_string)
        return response

    def get_file(self, filename, local_temp=None):
        if not local_temp:
            local_temp = os.environ.get('TMP', os.environ.get("TMPDIR", os.environ.get("TEMP")))

        responses = []
        for key in self.sessions:
            resp = self.__rtr_admin().execute_admin_command(base_command="get",
                                                            command_string=f"get \"{filename}\"",
                                                            session_id=self.sessions[key]['session_id'], persist=False)
            resp['aid'] = key
            resp['session_id'] = self.sessions[key]['session_id']
            responses.append(resp)

        for resp in responses:
            if "resources" in resp['body'] and len(resp['body']['resources']) > 0:
                for response in resp['body']['resources']:
                    outcome = self.__wait_for_response(response['cloud_request_id'])

                    if not outcome['error']:
                        file_id = None
                        while not file_id:
                            file_check = self.__rtr().list_files(session_id=resp['session_id'])
                            if len(file_check["body"]["resources"]) > 0:
                                file_id = None
                                for fid in file_check["body"]["resources"]:
                                    if fid['cloud_request_id'] == outcome['cloud_request_id']:
                                        file_id = fid['sha256']
                        if file_id:
                            download = self.__rtr().get_extracted_file_contents(
                                # Retrieve the file as a CrowdStrike secured zip file
                                sha256=file_id,  # Password will be "infected" even though this archive
                                session_id=resp['session_id'],  # DOES NOT contain malware, just a simple memory dump.
                                filename=f"DUMP_FILENAME.zip"
                            )
                            if isinstance(download, dict):  # Our download failed for some reason
                                logging.warning(download)  # Print the API response to stdout
                            else:
                                with open(  # We received a valid file download
                                        f"{local_temp}/{outcome['cloud_request_id']}.zip",
                                        "wb") as save_file:
                                    save_file.write(download)
                                archive = py7zr.SevenZipFile(  # nosec - Open our downloaded archive file using the
                                    f"{local_temp}/{outcome['cloud_request_id']}.zip",
                                    # password of "infected". Bandit will consider this
                                    mode="r",  # hard-coded password a low threat and cry about it.
                                    password="infected"
                                )

                                file_target = archive.getnames()[0]
                                archive.extractall(f"{local_temp}")
                                with open(f"{local_temp}/{file_target}", "rb") as ii:
                                    data = ii.read()

                                archive.close()
                                os.remove(f"{local_temp}/{outcome['cloud_request_id']}.zip")
                                os.remove(f"{local_temp}/{file_target}")

                                yield BulkOperationOutcome.from_get_file_success(auth=self._auth, client=self.client,
                                                                                 batch_id=self.batch_id,
                                                                                 session_id=resp['session_id'],
                                                                                 aid=resp['aid'],
                                                                                 cloud_request_id=outcome[
                                                                                     'cloud_request_id'],
                                                                                 content=data)

                    else:
                        yield BulkOperationOutcome.from_get_file_error_cloud_request(auth=self._auth,
                                                                                     client=self.client,
                                                                                     batch_id=self.batch_id,
                                                                                     session_id=resp['session_id'],
                                                                                     aid=resp['aid'],
                                                                                     cloud_request_id=outcome[
                                                                                         'cloud_request_id'],
                                                                                     error_msg=f"Failed to get file '{filename}' ({outcome['stderr']}) from {resp['aid']}")
            else:
                yield BulkOperationOutcome.from_get_file_error(auth=self._auth,
                                                               client=self.client,
                                                               batch_id=self.batch_id,
                                                               session_id=resp['session_id'],
                                                               aid=resp['aid'],
                                                               error_msg=f"Failed to get file '{filename}' ({str(resp)}")

    def isolate(self):
        req_body = {
            "ids": self.__host_ids()
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="contain", body=req_body)
        if "resources" in response['body'] and len(response['body']['resources']) > 0:
            for resource in response['body']['resources']:
                yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                       aid=resource['id'], command="isolate")

        if "errors" in response['body'] and len(response['body']['errors']) > 0:
            for error in response['body']['errors']:
                for aid in self.__host_ids():
                    if aid in error['message']:
                        yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client,
                                                               batch_id=self.batch_id,
                                                               aid=aid, command="isolate",
                                                               error_msg=error['message'])

    def lift_isolation(self):
        req_body = {
            "ids": self.__host_ids()
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="lift_containment", body=req_body)
        if "resources" in response['body'] and len(response['body']['resources']) > 0:
            for resource in response['body']['resources']:
                yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                       aid=resource['id'], command="lift_isolation")

        if "errors" in response['body'] and len(response['body']['errors']) > 0:
            for error in response['body']['errors']:
                for aid in self.__host_ids():
                    if aid in error['message']:
                        yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                               aid=aid, command="lift_isolation",
                                                               error_msg=error['message'])

    def hide_host(self):
        req_body = {
            "ids": self.__host_ids()
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="hide_host", body=req_body)
        if "resources" in response['body'] and len(response['body']['resources']) > 0:
            for resource in response['body']['resources']:
                yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                       aid=resource['id'], command="hide_host")

        if "errors" in response['body'] and len(response['body']['errors']) > 0:
            for error in response['body']['errors']:
                for aid in self.__host_ids():
                    if aid in error['message']:
                        yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client,
                                                               batch_id=self.batch_id,
                                                               aid=aid, command="hide_host",
                                                               error_msg=error['message'])

    def unhide_host(self):
        req_body = {
            "ids": self.__host_ids()
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="unhide_host", body=req_body)
        if "resources" in response['body'] and len(response['body']['resources']) > 0:
            for resource in response['body']['resources']:
                yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                       aid=resource['id'], command="unhide_host")

        if "errors" in response['body'] and len(response['body']['errors']) > 0:
            for error in response['body']['errors']:
                for aid in self.__host_ids():
                    if aid in error['message']:
                        yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client,
                                                               batch_id=self.batch_id,
                                                               aid=aid, command="unhide_host",
                                                               error_msg=error['message'])

    def suppress_detections(self):
        req_body = {
            "ids": self.__host_ids()
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="detection_suppress", body=req_body)
        if "resources" in response['body'] and len(response['body']['resources']) > 0:
            for resource in response['body']['resources']:
                yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                       aid=resource['id'], command="suppress_detections")

        if "errors" in response['body'] and len(response['body']['errors']) > 0:
            for error in response['body']['errors']:
                for aid in self.__host_ids():
                    if aid in error['message']:
                        yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client,
                                                               batch_id=self.batch_id,
                                                               aid=aid, command="suppress_detections",
                                                               error_msg=error['message'])

    def unsuppress_detections(self):
        req_body = {
            "ids": self.__host_ids()
        }
        response = self._auth.get_falcon_harness().command("PerformActionV2", action_name="detection_unsuppress", body=req_body)
        if "resources" in response['body'] and len(response['body']['resources']) > 0:
            for resource in response['body']['resources']:
                yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client, batch_id=self.batch_id,
                                                       aid=resource['id'], command="unsuppress_detections")

        if "errors" in response['body'] and len(response['body']['errors']) > 0:
            for error in response['body']['errors']:
                for aid in self.__host_ids():
                    if aid in error['message']:
                        yield BulkOperationOutcome.from_action(auth=self._auth, client=self.client,
                                                               batch_id=self.batch_id,
                                                               aid=aid, command="unsuppress_detections",
                                                               error_msg=error['message'])