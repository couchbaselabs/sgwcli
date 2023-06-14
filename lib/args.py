##
##

import argparse


class Parameters(object):

    def __init__(self):
        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument('-u', '--user', action='store', help="User Name", default="Administrator")
        parent_parser.add_argument('-p', '--password', action='store', help="User Password", default="password")
        parent_parser.add_argument('-h', '--host', action='store', help="Sync Gateway Hostname", default="localhost")
        parent_parser.add_argument('-s', '--ssl', action='store_true', help="Use SSL")
        parent_parser.add_argument('-k', '--keyspace', action='store', help='Keyspace')
        parent_parser.add_argument('-b', '--bucket', action='store', help='Bucket name')
        parent_parser.add_argument('-d', '--dbhost', action='store', help='Couchbase hostname', default="localhost")
        parent_parser.add_argument('-l', '--dblogin', action='store', help='Couchbase credentials', default="Administrator:password")
        parent_parser.add_argument('--dbuser', action='store', help='Couchbase user', default="Administrator")
        parent_parser.add_argument('--dbpass', action='store', help='Couchbase password', default="password")
        parent_parser.add_argument('--help', action='help', default=argparse.SUPPRESS, help='Show help message')
        parent_parser.add_argument('-D', '--debug', action='store_true', help="Debug output")
        parent_parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
        parent_parser.add_argument('-i', '--ignore', action='store_true', help="Ignore errors")
        db_parser = argparse.ArgumentParser(add_help=False)
        db_parser.add_argument('-n', '--name', action='store', help='Database name')
        db_parser.add_argument('-f', '--function', action='store', help='Sync Function')
        db_parser.add_argument('-r', '--replicas', action='store', help='Replica count', type=int, default=0)
        db_parser.add_argument('-g', '--get', action='store_true', help='Get Sync Function')
        user_parser = argparse.ArgumentParser(add_help=False)
        user_parser.add_argument('-n', '--name', action='store', help='Database name')
        user_parser.add_argument('-U', '--sguser', action='store', help='SGW user name', default="sguser")
        user_parser.add_argument('-P', '--sgpass', action='store', help='SGW user password', default="password")
        user_parser.add_argument('-f', '--field', action='store', help='Document field')
        user_parser.add_argument('-a', '--all', action='store_true', help='List all users')
        main_parser = argparse.ArgumentParser(add_help=False)
        main_parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show help message')
        subparser = main_parser.add_subparsers(dest='command')
        db_mode = subparser.add_parser('database', help="Database Operations", parents=[parent_parser, db_parser], add_help=False)
        subparser.add_parser('version', help="Show versions", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode = db_mode.add_subparsers(dest='db_command')
        db_sub_mode.add_parser('create', help="Create Database", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode.add_parser('delete', help="Delete Database", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode.add_parser('sync', help="Add Sync Function", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode.add_parser('resync', help="Sync Documents", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode.add_parser('list', help="List Databases", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode.add_parser('dump', help="Dump Databases", parents=[parent_parser, db_parser], add_help=False)
        db_sub_mode.add_parser('wait', help="Wait For Database Online", parents=[parent_parser, db_parser], add_help=False)
        user_mode = subparser.add_parser('user', help="User Operations", parents=[parent_parser, user_parser], add_help=False)
        user_sub_mode = user_mode.add_subparsers(dest='user_command')
        user_sub_mode.add_parser('create', help="Add User", parents=[parent_parser, user_parser], add_help=False)
        user_sub_mode.add_parser('delete', help="Delete User", parents=[parent_parser, user_parser], add_help=False)
        user_sub_mode.add_parser('list', help="List Users", parents=[parent_parser, user_parser], add_help=False)
        user_sub_mode.add_parser('map', help="Map values to users", parents=[parent_parser, user_parser], add_help=False)
        auth_mode = subparser.add_parser('auth', help="Auth Operations", parents=[parent_parser, user_parser], add_help=False)
        auth_sub_mode = auth_mode.add_subparsers(dest='auth_command')
        auth_sub_mode.add_parser('session', help="Get Session", parents=[parent_parser, user_parser], add_help=False)
        server_mode = subparser.add_parser('server', help="Server Operations", parents=[parent_parser, user_parser], add_help=False)
        server_sub_mode = server_mode.add_subparsers(dest='server_command')
        server_sub_mode.add_parser('info', help="Get Server Info", parents=[parent_parser, db_parser], add_help=False)
        self.parameters = main_parser.parse_args()

    @property
    def args(self):
        return self.parameters
