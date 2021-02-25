package nosql

import (
	nosqlDB "github.com/smallstep/nosql"
)

// DB is a struct that implements the AcmeDB interface.
type DB struct {
	db nosqlDB.DB
}
