#!/usr/bin/env python3
import json
import sys
import signal
import os
import traceback
import warnings
import logging
import inspect
import re
from lib.logging import CustomFormatter
from typing import Tuple
from lib.args import Parameters
from cbcmgr.cb_connect import CBConnect
from cbcmgr.cb_management import CBManager
from cbcmgr.httpsessionmgr import APISession
from cbcmgr.exceptions import HTTPForbidden, HTTPNotImplemented, PreconditionFailed, ConflictException
from cbcmgr.retry import retry
from cbcmgr.schema import ProcessSchema, Schema

warnings.filterwarnings("ignore")
logger = logging.getLogger()
ignore_errors = False
VERSION = '2.0.2'


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

    def import_schema(self, bucket: str) -> Schema:
        dbm = CBManager(self.host, self.username, self.password, ssl=self.ssl)
        contents = dbm.cluster_schema_dump()
        inventory = ProcessSchema(json_data=contents).inventory()
        return inventory.get(bucket)

    def merge(self, src: dict, dst: dict):
        for key in src:
            if key in dst:
                if isinstance(src[key], dict) and isinstance(dst[key], dict):
                    dst[key] = self.merge(src[key], dst[key])
                    continue
            dst[key] = src[key]
        return dst

    def keyspace_list(self, keyspace: str) -> Tuple[list[str], dict]:
        collection_list = []
        scope_struct = {}
        elements = keyspace.split('.')
        if len(elements) < 3:
            elements.append(r".*")
        if len(elements) < 3:
            elements.append(r".*")

        schema = self.import_schema(elements[0])

        for bucket in schema.buckets:
            for scope in bucket.scopes:
                if not re.match(f"^{elements[1]}$", scope.name) or scope.name == '_default':
                    continue
                for collection in scope.collections:
                    if not re.match(f"^{elements[2]}$", collection.name) or collection.name == '_default':
                        continue
                    keyspace_string = '.'.join([bucket.name, scope.name, collection.name])
                    logger.debug(f"Adding keyspace {keyspace_string}")
                    collection_list.append(keyspace_string)
                    add_struct = {
                        "scopes": {
                            scope.name: {
                                "collections": {
                                    collection.name: {}
                                }
                            }
                        }
                    }
                    scope_struct = self.merge(add_struct, scope_struct)

        if len(collection_list) == 0:
            collection_list.append(elements[0])

        return collection_list, scope_struct

    def get_users_by_field(self, field, keyspace):
        usernames = []
        collection_list, _ = self.keyspace_list(keyspace)
        db = CBConnect(self.host, self.username, self.password, ssl=self.ssl).connect()

        for collection in collection_list:
            query = f"select distinct {field} from {collection} where {field} is not missing;"
            try:
                results = db.cb_query(sql=query)
                if not results:
                    continue
                for record in results:
                    value = record[field]
                    usernames.append(f"{field}@{value}")
            except Exception as err:
                print(f"Can not get the values for {field}: {err}")
                sys.exit(1)

        return list(set(usernames))


class SGWDatabase(APISession):

    def __init__(self, node, *args, port=4985, ssl=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = node
        self.set_host(node, ssl, port)

    def create(self, bucket, name, replicas: int = 0, keyspace_struct: dict = None):
        data = {
            "import_docs": True,
            "enable_shared_bucket_access": True,
            "bucket": bucket,
            "name": name,
            "num_index_replicas": replicas
        }

        if keyspace_struct:
            data.update(keyspace_struct)

        logger.debug(f"Database create POST data: {json.dumps(data)}")

        try:
            self.api_put(f"/{name}/", data)
            print(f"Database {name} created for bucket {bucket}.")
        except HTTPForbidden:
            print(f"Bucket {bucket} does not exist.")
            sys.exit(1)
        except PreconditionFailed:
            print(f"Database {name} already exists.")
            if not ignore_errors:
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

    def expand_name(self, name) -> list[str]:
        if len(name.split('.')) != 1:
            return [name]

        response = self.api_get(f"/{name}/_config").json()
        if 'scopes' in response:
            keyspace_list = []
            for key in response['scopes']:
                prefix = f"{name}.{key}."
                for collection in response['scopes'][key].get('collections', {}).keys():
                    keyspace_list.append(f"{prefix}{collection}")
            return keyspace_list
        else:
            return [name]

    def sync_fun(self, name, filename):
        keyspace_list = self.expand_name(name)

        with open(filename, "r") as file:
            data = file.read()
            file.close()
            for keyspace in keyspace_list:
                try:
                    self.api_put_data(f"/{keyspace}/_config/sync", data, 'application/javascript')
                    print(f"Sync function created for database {keyspace}.")
                except HTTPForbidden:
                    print(f"Database {keyspace} does not exist.")
                    sys.exit(1)
                except Exception as err:
                    print(f"Sync function create failed for database {keyspace}: {err}")
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
            if 'scopes' in response:
                print("Scopes:")
                print(json.dumps(response['scopes'], indent=2))
        except HTTPForbidden:
            print(f"Database {name} does not exist.")
            sys.exit(1)
        except Exception as err:
            print(f"Database list failed for {name}: {err}")
            sys.exit(1)

    def list_all(self):
        try:
            response = self.api_get("/_all_dbs").json()
            for database in response:
                print(database)
        except Exception as err:
            print(f"Database list failed: {err}")
            sys.exit(1)

    @retry(factor=0.5, retry_count=20)
    def ready_wait(self, name):
        self.api_get(f"/{name}/_config").json()

    def dump(self, name):
        keyspace_list = self.expand_name(name)

        for keyspace in keyspace_list:
            print(f"Keyspace {keyspace}:")
            try:
                response = self.api_get(f"/{keyspace}/_all_docs").json()
                for item in response["rows"]:
                    document = self.api_get(f"/{keyspace}/_raw/{item['id']}").json()
                    sequence = document['_sync']['sequence']
                    offset = document['_sync']['recent_sequences'].index(sequence)
                    print(f"Key: {item['key']} "
                          f"Id: {item['id']} "
                          f"Channels: {document['_sync']['history']['channels'][offset]}")
            except HTTPForbidden:
                print(f"Database {keyspace} does not exist.")
                sys.exit(1)
            except Exception as err:
                print(f"Database list failed for {keyspace}: {err}")
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
        except ConflictException:
            print(f"User {username} already exists.")
            if not ignore_errors:
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


class SGWAuth(APISession):

    def __init__(self, node, *args, port=4985, ssl=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = node
        self.set_host(node, ssl, port)

    def get_session(self, name, user):
        data = {
            "name": user
        }
        response = self.api_post(f"/{name}/_session", data)
        print(json.dumps(json.loads(response.response), indent=2))


class SGWServer(APISession):

    def __init__(self, node, *args, port=4985, ssl=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = node
        self.set_host(node, ssl, port)

    def get_info(self):
        response = self.api_get("/").json()
        return response

    def print_info(self):
        info = self.get_info()
        if info.get('version'):
            name, version = info.get('version').split('/')[0:2]
            version = version.split('(', 1)[0]
            print(f"{name} {version}")
        else:
            print("Can not get server information")


class RunMain(object):

    def __init__(self):
        pass

    @staticmethod
    def run(parameters):
        logger.info(f"Sync Gateway CLI ({VERSION})")
        keyspace_struct = None

        if parameters.command == 'version':
            sys.exit(0)

        if parameters.command == 'database':
            sgdb = SGWDatabase(parameters.host, parameters.user, parameters.password)
            if parameters.db_command == "create":
                if not parameters.name:
                    parameters.name = parameters.bucket
                if parameters.keyspace:
                    cbdb = CBSInterface(parameters.dbhost, parameters.dbuser, parameters.dbpass)
                    _, keyspace_struct = cbdb.keyspace_list(parameters.keyspace)
                sgdb.create(parameters.bucket, parameters.name, parameters.replicas, keyspace_struct)
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
                if parameters.name:
                    sgdb.list(parameters.name)
                else:
                    sgdb.list_all()
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
                cbdb = CBSInterface(parameters.dbhost, parameters.dbuser, parameters.dbpass)
                usernames = cbdb.get_users_by_field(parameters.field, parameters.keyspace)
                for username in usernames:
                    sguser.create(parameters.name, username, parameters.sgpass, channels=f"channel.{username}")
        elif parameters.command == 'auth':
            sgauth = SGWAuth(parameters.host, parameters.user, parameters.password)
            if parameters.auth_command == "session":
                sgauth.get_session(parameters.name, parameters.sguser)
        elif parameters.command == 'server':
            sgserver = SGWServer(parameters.host, parameters.user, parameters.password)
            if parameters.server_command == "info":
                sgserver.print_info()


def main():
    global logger, ignore_errors
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

    if parameters.ignore:
        ignore_errors = True

    RunMain().run(parameters)


if __name__ == '__main__':
    try:
        main()
    except SystemExit as e:
        sys.exit(e.code)
