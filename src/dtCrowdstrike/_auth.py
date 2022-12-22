from falconpy import APIHarness
from falconpy import OAuth2
from datetime import datetime

import logging


class _Auth(object):

    def __init__(self, client_secret, client_id) -> None:
        super().__init__()
        self.client_secret = client_secret
        self.client_id = client_id
        self.auth_time = None
        self.falcon_harness = None
        self.falcon_auth = None
        self.__auth()

    def __auth(self):
        try:
            self.falcon_harness = APIHarness(client_id=self.client_id, client_secret=self.client_secret)
            self.falcon_auth = OAuth2(client_id=self.client_id, client_secret=self.client_secret)
            self.auth_time = datetime.now()
            logging.info(f'Authenticated to Crowdstrike at {str(self.auth_time)}')
        except Exception as ex:
            logging.exception(f'Failed to authenticate to Crowdstrike: {str(ex)}')
            raise ex

    def __needs_reauth(self):
        return not self.auth_time or (datetime.now() - self.auth_time).seconds > 600

    def get_falcon_harness(self):
        if self.__needs_reauth():
            self.__auth()
        return self.falcon_harness

    def get_falcon_auth(self):
        if self.__needs_reauth():
            self.__auth()
        return self.falcon_auth

    def get_last_auth_time(self):
        return self.auth_time

    def close(self):
        self.falcon_harness = None
        self.falcon_auth = None
        self.auth_time = None
