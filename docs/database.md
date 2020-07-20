# Step Certificates Database

`step certificates` uses a simple key-value interface over popular database
implementations to store persistent certificate management meta-data.

Our recommended default database implementation is
[nosql-Badger](https://github.com/smallstep/nosql/badger) - a NoSQL interface
over the popular [Badger](https://github.com/dgraph-io/badger) database.

## What will the database store?

As a first pass, the database layer will store every certificate (along with
metadata surrounding the provisioning of the certificate) and revocation data
that will be used to enforce passive revocation.

## Implementations

Current implementations include Badger (default), BoltDB, and MysQL.

- [ ] Memory
- [x] No database
- [x] [BoltDB](https://github.com/etcd-io/bbolt) -- etcd fork.
- [x] [Badger](https://github.com/dgraph-io/badger)
- [x] [MySQL/MariaDB](https://github.com/go-sql-driver/mysql)
- [ ] PostgreSQL
- [ ] Cassandra

Let us know which integration you would like to see next by opening an issue or PR.

## Configuration

Configuring `step certificates` to use a database is as simple as adding a
top-level `db` stanza to `$(step path)/config/ca.json`.  Below are a few examples for supported databases:

### Badger

```
{
  ...
  "db": {
    "type": "badger",
    "dataSource": "./.step/db",
    "valueDir": "./.step/valuedb"
    "badgerFileLoadingMode": "MemoryMap"
  },
  ...
}
```

#### Options for `db`:

* `type`
    * `badger` - currently refers to Badger V1. However, as Badger V1 is deprecated,
    this will refer to Badger V2 starting with a the next major version release.
    * `badgerV1` - explicitly select Badger V1.
    * `badgerV2` - explicitly select Badger V2. Anyone looking to use Badger V2
    will need to set it explicitly until it becomes the default.
* `dataSource` - path, database directory.
* `valueDir` [optional] - path, value directory, only if different from `dataSource`.
* `badgerFileLoadingMode` [optional] - can be set to `FileIO` (instead of the default
        `MemoryMap`) to avoid memory-mapping log files. This can be
        useful in environments with low RAM. Make sure to use `badgerV2` as the
        database `type` if using this option.
    * `MemoryMap` - default.
    * `FileIO` - This can be useful in environments with low RAM.

### BoltDB

```
{
  ...
  "db": {
    "type": "bbolt",
    "dataSource": "./stepdb"
  },
  ...
},
```

### MySQL

```
{
  ...
  "db": {
    "type": "mysql",
    "dataSource": "user:password@tcp(127.0.0.1:3306)/",
    "database": "myDatabaseName"
  },
  ...
},
```

## Schema

As the interface is a key-value store, the schema is very simple. We support
`tables`, `keys`, and `values`. An entry in the database is a `[]byte value`
that is indexed by `[]byte table` and `[]byte key`.

## Data Backup

Backing up your data is important, and it's good hygiene. We chose
[Badger](https://github.com/dgraph-io/badger) as our default file based data
storage backend because it has mature tooling for running common database
tasks. See the [documentation](https://github.com/dgraph-io/badger#database-backup)
for a guide on backing up your data.
