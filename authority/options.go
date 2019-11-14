package authority

import (
	"github.com/smallstep/certificates/db"
)

// Option sets options to the Authority.
type Option func(*Authority)

// WithDatabase sets an already initialized authority database to a new
// authority. This option is intended to be use on graceful reloads.
func WithDatabase(db db.AuthDB) Option {
	return func(a *Authority) {
		a.db = db
	}
}
