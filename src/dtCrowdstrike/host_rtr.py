import logging
import os
import random
import time

import py7zr
import csv
import io

from falconpy import RealTimeResponse as RTR, RealTimeResponseAdmin as RTRAdmin


class RealTimeResponse(object):

    def __init__(self, auth, aid, host) -> None:
        super().__init__()
        self._auth = auth
        self.aid = aid
        self.host = host
        self.session_ids = []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        for session_id in self.session_ids:
            self.__rtr().delete_session(session_id=session_id)

    def __rtr(self):
        return RTR(auth_object=self._auth.get_falcon_auth())

    def __rtr_admin(self):
        return RTRAdmin(auth_object=self._auth.get_falcon_auth())

    def __wait_for_response(self, cloud_request_id):
        running = True
        stderr = None
        stdout = None
        while running:
            time.sleep(random.randint(5, 10))  # Give it some time before the next check on the status
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

    def __init_rtr_session(self):
        session_resp = self.__rtr().init_session(device_id=self.aid)
        if "resources" in session_resp["body"] and len(session_resp["body"]["resources"]) == 1:
            session_id = session_resp["body"]["resources"][0]["session_id"]
            self.session_ids.append(session_id)
            return session_id
        else:
            raise Exception(f'Failed to establish RTR Session with {self.aid}.  Response: {str(session_resp)}')

    def run_command(self, command, parameters=None, timeout=None, encapsulate="```"):
        session_id = self.__init_rtr_session()
        command_string = f"{command}"
        if parameters and encapsulate not in parameters:
            command_string = f"{command} {encapsulate}{parameters}{encapsulate}"
        elif parameters and encapsulate in parameters:
            command_string = f"{command} {parameters}"
        if timeout:
            command_string = f"{command_string} -Timeout={str(timeout)}"
        resp = self.__rtr_admin().execute_admin_command(base_command=command,
                                                        command_string=f"{command_string}",
                                                        session_id=session_id, persist=False)
        outcome = None
        if "resources" in resp['body'] and len(resp['body']['resources']) > 0:
            for response in resp['body']['resources']:
                outcome = self.__wait_for_response(response['cloud_request_id'])

        else:
            raise Exception(f"Failed to execute command '{command_string}' ({str(resp)}")

        outcome['resource'] = self.aid
        outcome['command'] = command_string
        return outcome

    def runscript(self, script):
        outcome = self.run_command(command="runscript", timeout=3600, parameters=f"-Raw=```{script}```")
        outcome['script'] = script
        return outcome

    def get_counters(self):
        if self.host.is_windows():
            with open(os.path.dirname(__file__) + "/_resources/counters.ps1", 'r') as ps1:
                script = ps1.read()

            result = self.runscript(script)
            if not result['error']:
                data = self.get_file("C:/counters.csv")
                outcome = self.delete_file("C:/counters.csv")
                if outcome['error']:
                    logging.warning(f'Failed to delete temporary file on destination: {str(outcome)}')

                counters = []
                for row in csv.DictReader(
                        io.StringIO(data.decode("utf-8").replace(f"\\\\{self.host.get_hostname().lower()}\\", ""))):
                    counters.append(row)

                return counters
            else:
                raise Exception(f'Failed to run counters process: {str(result)}')
        else:
            raise Exception(f'The host {self.host.get_hostname()} does not support this request.  Only supported on '
                            f'Windows.')

    def file_exists(self, file_absolute_path):
        outcome = self.run_command(command="ls", parameters=f"{file_absolute_path}", encapsulate="")
        return not outcome['error']

    def get_file(self, filename, local_temp=None):
        if not local_temp:
            local_temp = os.environ.get('TMP', os.environ.get("TMPDIR"))
        session_id = self.__init_rtr_session()
        resp = self.__rtr_admin().execute_admin_command(base_command="get",
                                                        command_string=f"get \"{filename}\"",
                                                        session_id=session_id,
                                                        persist=False)
        outcome = None
        if "resources" in resp['body'] and len(resp['body']['resources']) > 0:
            for response in resp['body']['resources']:
                outcome = self.__wait_for_response(response['cloud_request_id'])

            if not outcome['error']:
                file_id = None
                while not file_id:
                    file_check = self.__rtr().list_files(session_id=session_id)
                    if len(file_check["body"]["resources"]) > 0:
                        file_id = None
                        for fid in file_check["body"]["resources"]:
                            if fid['cloud_request_id'] == outcome['cloud_request_id']:
                                file_id = fid['sha256']
                if file_id:
                    download = self.__rtr().get_extracted_file_contents(
                        # Retrieve the file as a CrowdStrike secured zip file
                        sha256=file_id,  # Password will be "infected" even though this archive
                        session_id=session_id,  # DOES NOT contain malware, just a simple memory dump.
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
                        enc = "utf-8"
                        with open(f"{local_temp}/{file_target}", "rb") as ii:
                            data = ii.read()

                        archive.close()
                        os.remove(f"{local_temp}/{outcome['cloud_request_id']}.zip")
                        os.remove(f"{local_temp}/{file_target}")

                        return data

            else:
                raise Exception(f"Failed to get file '{filename}' ({outcome['stderr']}")

        else:
            raise Exception(f"Failed to get file '{filename}' ({str(resp)}")

    def delete_file(self, filename):
        session_id = self.__init_rtr_session()
        resp = self.__rtr_admin().execute_admin_command(base_command="rm",
                                                        command_string=f"rm ```{filename}```",
                                                        session_id=session_id, persist=False)
        outcome = None
        if "resources" in resp['body'] and len(resp['body']['resources']) > 0:
            for response in resp['body']['resources']:
                outcome = self.__wait_for_response(response['cloud_request_id'])

        else:
            raise Exception(f"Failed to delete '{filename}' ({str(resp)}")

        if outcome['error']:
            outcome = self.runscript(f"del {filename}")

        return outcome

    def get_processes(self):
        if self.host.is_windows():
            response = self.runscript(script="wmic process")
            if not response['error']:
                return response['stdout']
        else:
            raise Exception(f'The host {self.host.get_hostname()} does not support this request.  Only supported on '
                            f'Windows.')

    def get_netstat(self):
        if self.host.is_windows():
            response = self.runscript(script="netstat -a")
            if not response['error']:
                return response['stdout']
        else:
            raise Exception(f'The host {self.host.get_hostname()} does not support this request.  Only supported on '
                            f'Windows.')
