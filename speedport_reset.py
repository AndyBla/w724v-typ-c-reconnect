import requests
import re
import hashlib
import json
import time
import os
import logging

from configparser import ConfigParser


class RouterUrl(object):
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.router = 'http://' + self.ip_address
        self.login = self.router + '/data/Login.json'
        self.main = self.router + '/html/content/overview/index.html?lang=de'
        self.reset_connection_json = self.router + "/data/Connect.json"


class SpeedPortW724V_Typ_C(object):
    def __init__(self, ip_address, pw):

        self._ip_address = ip_address
        self._router_url = RouterUrl(self._ip_address)
        self._pw = pw

        self._session = None
        self._challange = None
        self._cookie = None
        self._csrf_token = None

    # extract hash challenge from session
    def __check_ip(self):
        try:
            page_object = self._session.get(self._router_url.router)
            regex = re.compile(r'Speedport')

            results = re.findall(regex, page_object.text)
            if len(results) > 0:
                return True
            else:
                logging.warning("Probably not a speedport router! May not work!")
                return True


        except requests.ConnectionError:
            logging.error("Can't connect to {ip}!".format(ip=self._ip_address))
            raise ValueError("Can't connect to {ip}!".format(ip=self._ip_address))

    def __enter__(self):
        if self._session is None:
            self._session = requests.Session()
        else:
            logging.error("Session already started!")
            return

        # check router ip, raise error
        self.__check_ip()

        # get challange key
        self._challange = self.__get_hash_challenge()
        logging.debug("Challange Key: {key}".format(key=self._challange))

        # login
        self._login_router()

        return self

    def __exit__(self, type, value, traceback):
        # logout
        self._logout_router()

        if self._session is not None:
            self._session.__exit__()
            self._session = None
        else:
            logging.error("Session already closed.")

    def _login_router(self):
        # login
        pwd = SpeedPortW724V_Typ_C.__encrypt(self._pw, self._challange)

        page = self._session.post(self._router_url.login,
                                  data={'showpw': '0', 'csrf_token': 'nulltoken', 'password': pwd,
                                        'challengev': self._challange})

        json_data = self.__to_json(page)

        for jobj in json_data:
            # error
            if jobj['varid'] == 'login' and jobj['varvalue'] == 'failed':
                logging.error("Login failed! -- {data}".format(data=json_data))
                raise ValueError("Login failed!")
            elif jobj['varid'] == 'login' and jobj['varvalue'] == 'success':
                logging.info("Login success!")
        # get cookie
        self._cookie = page.cookies
        # get csrf_token
        self._csrf_token = self.__get_token()
        logging.debug("csrf token: {token}".format(token=self._csrf_token))

    def _logout_router(self):

        page = self._session.post(self._router_url.login,
                                  data={'csrf_token': self._csrf_token, 'logout': 'byby'})

        json_data = self.__to_json(page)

        for jobj in json_data:
            # error
            if jobj['varid'] == 'status' and jobj['varvalue'] == 'ok':
                logging.info("Logout!")
                self._cookie = None
                self._challange = None
                self._csrf_token = None
            else:
                logging.error("Error in Logout Method!")

    def __check_login(self):
        if self._challange is not None and self._cookie is not None and self._csrf_token is not None:
            return True
        else:
            return False

    # extract hash challenge from session
    def __get_hash_challenge(self):

        page_object = self._session.get(self._router_url.router)

        regex = re.compile(r'var\s*challenge\s*=\s*\"(\w*)')

        results = re.findall(regex, page_object.text)
        if len(results) > 0:
            return results[0]
        else:
            raise ValueError("No Challenge found!")

    # extract token from session
    def __get_token(self):
        page_object = self._session.get(self._router_url.main)

        regex = re.compile(r'var\s*csrf_token\s*=\s*\"(\w*)')

        results = re.findall(regex, page_object.text)
        if len(results) > 0:
            return results[0]
        else:
            raise ValueError("No token found!")

    @staticmethod
    def __encrypt(pwd, challenge):
        # max len PW 12 chars
        if len(pwd) > 12:
            pwd = pwd[:12]
        return hashlib.sha256((challenge + ":" + pwd).encode('utf-8')).hexdigest()

    # converto to json object, error handling komma
    def __to_json(self, page):
        try:
            json_data = page.json()
            return json_data
        # value Error last ","
        except ValueError as e:
            head, _sep, tail = page.text.rpartition(",")
            json_data = head + tail
            json_data = json.loads(json_data)
            return json_data

    def reset_connection(self, sleep_duration):
        logging.info("Start reconnect.")

        start_ip = router._current_IP()

        # reset json
        address = self._router_url.reset_connection_json

        logging.info("Disable connection...")

        data = {'req_connect': "disabled",
                'csrf_token': self._csrf_token}
        self._session.post(address, data=data)

        time.sleep(sleep_duration)

        logging.info("Enable connection...")
        data = {'req_connect': "online",
                'csrf_token': self._csrf_token}
        self._session.post(address, data=data)
        time.sleep(sleep_duration)

        end_ip = router._current_IP()
        logging.info("End reconnect.")
        logging.info("Old IP:{ip_old}, new IP:{ip_new}.".format(ip_old=start_ip, ip_new=end_ip))

    def _current_IP(self, timeout_s=5, retries=10):

        while retries != 0:
            try:
                page = self._session.get('http://ipecho.net/plain', timeout=timeout_s)
                return page.text
            except:
                # print(".", end="", flush=True)
                retries -= 1


if __name__ == '__main__':

    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO),  # filename='example.log'

    print("Reconnect-Script W724V Typ C")

    if not os.path.exists("settings.ini"):
        file = open('settings.ini', 'w')
        parser = ConfigParser()
        parser.add_section('speedport_reconnect')
        parser.set('speedport_reconnect', 'ip', '0.0.0.0')
        parser.set('speedport_reconnect', 'password', 'secret')
        parser.write(file)
        logging.info("Settings.ini created!")
        exit(0)
    else:
        parser = ConfigParser()
        parser.read('settings.ini')

        ip = parser.get('speedport_reconnect', 'ip')
        password = parser.get('speedport_reconnect', 'password')

        with SpeedPortW724V_Typ_C(ip, pw=password) as router:
            router.reset_connection(5)

