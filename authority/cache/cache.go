package cache

import (
	"context"
	"errors"
	"sync"
)

var ErrNotFound = errors.New("not found")

type Cache interface {
	Get(context.Context, string) ([]byte, error)
	Set(context.Context, string, []byte) error
	Delete(context.Context, string) error
}

type Getter interface {
	Get(ctx context.Context, key string) ([]byte, error)
}

// A GetterFunc implements Getter with a function.
type GetterFunc func(ctx context.Context, key string) ([]byte, error)

func (f GetterFunc) Get(ctx context.Context, key string) ([]byte, error) {
	return f(ctx, key)
}

type Pool interface {
	New(name string, getter Getter) Cache
	Get(name string) (Cache, bool)
}

func DefaultPool() Pool {
	return &defaultPool{
		caches: make(map[string]Cache),
	}
}

type defaultPool struct {
	mu     sync.RWMutex
	caches map[string]Cache
}

func (p *defaultPool) New(name string, getter Getter) Cache {
	c := &mapCache{
		m:      new(sync.Map),
		getter: getter,
	}
	p.mu.Lock()
	p.caches[name] = c
	p.mu.Unlock()
	return c
}

func (p *defaultPool) Get(name string) (Cache, bool) {
	p.mu.RLock()
	c, ok := p.caches[name]
	p.mu.RUnlock()
	return c, ok
}

type mapCache struct {
	name   string
	m      *sync.Map
	getter Getter
}

func (m *mapCache) Get(ctx context.Context, key string) ([]byte, error) {
	v, ok := m.m.Load(key)
	if !ok {
		b, err := m.getter.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		m.m.Store(key, b)
		return b, nil
	}
	return v.([]byte), nil
}

func (m *mapCache) Set(ctx context.Context, key string, value []byte) error {
	m.m.Store(key, value)
	return nil
}

func (m *mapCache) Delete(ctx context.Context, key string) error {
	m.m.Delete(key)
	return nil
}
