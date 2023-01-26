package q

import (
	ryboeq "github.com/ryboe/q"
)

func Q(v ...interface{}) {
	// TODO(hs): do or do not call ryboeq.Q based on e.g. debug flag,
	// runtime (go run vs. build), based on compiled or not. Goal would be
	// to not debug in prod builds at all times. Ideally, never leave a leftover
	// call to q.Q in the code, so panic if there is?
	ryboeq.Q(v...)
}
