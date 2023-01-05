# sgwcli

Couchbase Sync Gateway CLI

## Disclaimer

> This is not an officially supported utility

Database Commands:

| Command | Description                                 |
|---------|---------------------------------------------|
| create  | Create SGW database (connect to CBS Bucket) |
| delete  | Delete a database                           |
| sync    | Manage Sync Function for database           |
| resync  | Reprocess documents with sync function      |
| list    | List database                               |
| dump    | Dump synced document details                |

User Commands:

| Command | Description                          |
|---------|--------------------------------------|
| create  | Create users                         |
| delete  | Delete user                          |
| list    | List users                           |
| map     | Create users based on document field |

Database parameters:

| Parameter      | Description                   |
|----------------|-------------------------------|
| -b, --bucket   | Bucket                        |
| -n, --name     | Database name                 |
| -f, --function | Sync Function file            |
| -r, --replicas | Number of replicas            |
| -g, --get      | Display current Sync Function |

User parameters:

| Parameter      | Description                                           |
|----------------|-------------------------------------------------------|
| -n, --name     | Database name                                         |
| -U, --sguser   | Sync Gateway user name                                |
| -P, --sgpass   | Sync Gateway user password                            |
| -d, --dbhost   | Couchbase server connect name or IP (for map command) |
| -l, --dblogin  | Couchbase server credentials in form user:password    |
| -f, --field    | Document field to map                                 |
| -k, --keyspace | Keyspace with documents for map                       |
| -a, --all      | List all users                                        |

Examples:

Create Sync Gateway database "sgwdb" that is connected to bucket "demo":
```
sgwcli database create -h hostname -n sgwdb -b demo
```

Get information about database "sgwdb":
```
sgwcli database list -h hostname -n sgwdb
```

Display information about documents in the database including the latest channel assignment:
```
sgwcli database dump -h hostname -n sgwdb
```

Create a Sync Gateway database user:
```
sgwcli user create -h hostname -n sgwdb --sguser sgwuser --sgpass "password"
```

Display user details:
```
sgwcli user list -h hostname -n sgwdb --sguser sgwuser
```

List all database users:
```
sgwcli user list -h hostname -n sgwdb -a
```

Create users in database "sgwdb" based on the unique values for document value "field_name" in keyspace "demo":
```
sgwcli user map -h sgwhost -d cbshost -f field_name -k demo -n sgwdb
```

Add Sync Function:
```
sgwcli database sync -h hostname -n sgwdb -f /home/user/demo.js
```

Display Sync Function:
```
sgwcli database sync -h hostname -n sgwdb -g
```

Delete user:
```
sgwcli user delete -h hostname -n sgwdb --sguser sgwuser
```

Delete database "sgwdb":
```
sgwcli database delete -h hostname -n sgwdb
```
