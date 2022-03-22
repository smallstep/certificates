// Package buffer implements a reusable buffer pool.
package buffer

import (
	"bytes"
	"sync"
)

func Get() *bytes.Buffer {
	return pool.Get().(*bytes.Buffer)
}

func Put(b *bytes.Buffer) {
	b.Reset()

	pool.Put(b)
}

var pool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}
