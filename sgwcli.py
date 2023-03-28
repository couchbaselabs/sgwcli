#!/usr/bin/env python3

import sys
import signal
import os
import traceback
import warnings
import logging
import inspect
from lib.logging import CustomFormatter
from lib.args import Parameters
from cbcmgr.cb_connect import CBConnect
from cbcmgr.httpsessionmgr import APISession
from cbcmgr.exceptions import HTTPForbidden, HTTPNotImplemented
from cbcmgr.retry import retry

warnings.filterwarnings("ignore")
logger = logging.getLogger()
VERSION = '1.1'


def break_signal_handler(signum, frame):
    signal_name = signal.Signals(signum).name
    (filename, line, function, lines, index) = inspect.getframeinfo(frame)
    logger.debug(f"received break signal {signal_name} in {filename} {function} at line {line}")
    if 'SGW_CLI_DEBUG_LEVEL' in os.environ:
        if int(os.environ['SGW_CLI_DEBUG_LEVEL']) == 0:
            tb = traceback.format_exc()
            print(tb)
    print("")
    print("Break received, aborting.")
    sys.exit(1)


class CBSInterface(object):

    def __init__(self, hostname, username, password, ssl=True):
        self.host = hostname
        self.username = username
        self.password = password
        self.ssl = ssl

    def get_values(self, field, keyspace):
        query = f"select distinct {field} from {keyspace} where {field} is not missing;"
        usernames = []

        try:
            db = CBConnect(self.host, self.username, self.password, ssl=self.ssl).connect()
            results = db.cb_query(sql=query)
            for record in results:
                value = record[field]
                usernames.append(f"{field}@{value}")
            return usernames
        except Exception as err:
            print(f"Can not get the values for {field}: {err}")
            sys.exit(1)


class SGWDatabase(APISession):

    def __init__(self, node, *args, port=4985, ssl=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = node
        self.set_host(node, ssl, port)

    def create(self, bucket, name, replicas=0):
        data = {
            "import_docs": True,
            "enable_shared_bucket_access": True,
            "bucket": bucket,
            "name": name,
            "num_index_replicas": replicas
        }
        try:
            self.api_put(f"/{name}/", data)
            print(f"Database {name} created for bucket {bucket}.")
        except HTTPForbidden:
            print(f"Bucket {bucket} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database create failed for bucket {bucket}: {err}")
            sys.exit(1)

    def delete(self, name):
        try:
            self.api_delete(f"/{name}/")
            print(f"Database {name} deleted.")
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database delete failed for {name}: {err}")
            sys.exit(1)

    def sync_fun(self, name, filename):
        with open(filename, "r") as file:
            data = file.read()
            file.close()
            try:
                self.api_put_data(f"/{name}/_config/sync", data, 'application/javascript')
                print(f"Sync function created for database {name}.")
            except HTTPForbidden:
                print(f"Database {name} does not exist.")
                sys.exit(1)
            except Exception as err:
                print(f"Sync function create failed for database {name}: {err}")
                sys.exit(1)

    def get_sync_fun(self, name):
        try:
            response = self.api_get(f"/{name}/_config/sync")
            print(response.response)
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Sync function get failed for database {name}: {err}")
            sys.exit(1)

    def resync(self, name):
        try:
            self.api_post(f"/{name}/_offline", None)
            self.api_post(f"/{name}/_resync", None)
            print("Waiting for resync to complete")
            self.resync_wait(name)
            print("Resync complete")
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Resync failed for database {name}: {err}")
            sys.exit(1)

    @retry(factor=0.5, retry_count=20)
    def resync_wait(self, name):
        self.api_post(f"/{name}/_online", None)

    def list(self, name):
        try:
            response = self.api_get(f"/{name}/_config").json()
            print(f"Bucket:   {response['bucket']}")
            print(f"Name:     {response['name']}")
            print(f"Replicas: {response['num_index_replicas']}")
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database list failed for {name}: {err}")
            sys.exit(1)

    @retry(factor=0.5, retry_count=20)
    def ready_wait(self, name):
        self.api_get(f"/{name}/_config").json()

    def dump(self, name):
        try:
            response = self.api_get(f"/{name}/_all_docs").json()
            for item in response["rows"]:
                document = self.api_get(f"/{name}/_raw/{item['id']}").json()
                sequence = document['_sync']['sequence']
                offset = document['_sync']['recent_sequences'].index(sequence)
                print(f"Key: {item['key']} "
                      f"Id: {item['id']} "
                      f"Channels: {document['_sync']['history']['channels'][offset]}")
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database list failed for {name}: {err}")
            sys.exit(1)


class SGWUser(APISession):

    def __init__(self, node, *args, port=4985, ssl=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = node
        self.set_host(node, ssl, port)

    def create(self, dbname, username, password, channels=None):
        if channels is None:
            admin_channels = "*"
        else:
            admin_channels = channels
        data = {
            "password": password,
            "admin_channels": [admin_channels],
            "disabled": False
        }
        try:
            self.api_put(f"/{dbname}/_user/{username}", data)
            print(f"User {username} created for database {dbname}.")
        except HTTPForbidden:
            print(f"Database {dbname} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"User create failed for database {dbname}: {err}")
            sys.exit(1)

    def delete(self, name, username):
        try:
            self.api_delete(f"/{name}/_user/{username}")
            print(f"User {username} deleted from {name}.")
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except HTTPNotImplemented:
            print(f"User {username} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database delete failed for {name}: {err}")
            sys.exit(1)

    def list(self, name, username=None):
        try:
            if username:
                response = self.api_get(f"/{name}/_user/{username}").json()
                print(f"Name:           {response['name']}")
                print(f"Admin channels: {response['admin_channels']}")
                print(f"All channels:   {response.get('all_channels', 'None')}")
                print(f"Roles:          {response.get('admin_roles', 'None')}")
                print(f"Disabled:       {response.get('disabled', 'None')}")
            else:
                response = self.api_get(f"/{name}/_user/").json()
                for item in response:
                    print(item)
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except HTTPNotImplemented:
            print(f"User {username} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database list failed for {name}: {err}")
            sys.exit(1)


class RunMain(object):

    def __init__(self):
        pass

    @staticmethod
    def run(parameters):
        logger.info(f"Sync Gateway CLI ({VERSION})")

        if parameters.command == 'version':
            sys.exit(0)

        if parameters.command == 'database':
            sgdb = SGWDatabase(parameters.host, parameters.user, parameters.password)
            if parameters.db_command == "create":
                if not parameters.name:
                    parameters.name = parameters.bucket
                sgdb.create(parameters.bucket, parameters.name, parameters.replicas)
            elif parameters.db_command == "delete":
                sgdb.delete(parameters.name)
            elif parameters.db_command == "sync":
                if parameters.get:
                    sgdb.get_sync_fun(parameters.name)
                else:
                    sgdb.sync_fun(parameters.name, parameters.function)
                    sgdb.resync(parameters.name)
            elif parameters.db_command == 'resync':
                sgdb.resync(parameters.name)
            elif parameters.db_command == "list":
                sgdb.list(parameters.name)
            elif parameters.db_command == "dump":
                sgdb.dump(parameters.name)
            elif parameters.db_command == "wait":
                sgdb.ready_wait(parameters.name)
        elif parameters.command == 'user':
            sguser = SGWUser(parameters.host, parameters.user, parameters.password)
            if parameters.user_command == "create":
                sguser.create(parameters.name, parameters.sguser, parameters.sgpass)
            elif parameters.user_command == "delete":
                sguser.delete(parameters.name, parameters.sguser)
            elif parameters.user_command == "list":
                if parameters.all:
                    sguser.list(parameters.name)
                else:
                    sguser.list(parameters.name, parameters.sguser)
            elif parameters.user_command == "map":
                dbuser = parameters.dblogin.split(':')[0]
                dbpass = parameters.dblogin.split(':')[1]
                cbdb = CBSInterface(parameters.dbhost, dbuser, dbpass)
                usernames = cbdb.get_values(parameters.field, parameters.keyspace)
                for username in usernames:
                    sguser.create(parameters.name, username, parameters.sgpass, channels=f"channel.{username}")


def main():
    global logger
    signal.signal(signal.SIGINT, break_signal_handler)
    default_debug_file = 'debug.log'
    debug_file = os.environ.get("SGW_CLI_DEBUG_FILE", default_debug_file)
    arg_parser = Parameters()
    parameters = arg_parser.args

    try:
        if parameters.debug:
            logger.setLevel(logging.DEBUG)

            try:
                open(debug_file, 'w').close()
            except Exception as err:
                print(f"[!] Warning: can not clear log file {debug_file}: {err}")

            file_handler = logging.FileHandler(debug_file)
            file_formatter = logging.Formatter(logging.BASIC_FORMAT)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        elif parameters.verbose or parameters.command == 'version':
            logger.setLevel(logging.INFO)
        else:
            logger.setLevel(logging.ERROR)
    except (ValueError, KeyError):
        pass

    screen_handler = logging.StreamHandler()
    screen_handler.setFormatter(CustomFormatter())
    logger.addHandler(screen_handler)

    RunMain().run(parameters)


if __name__ == '__main__':
    try:
        main()
    except SystemExit as e:
        sys.exit(e.code)
