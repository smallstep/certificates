package admin

// ContextKey is the key type for storing and searching for
// Admin API objects in request contexts.
type ContextKey string

const (
	// AdminContextKey account key
	AdminContextKey = ContextKey("admin")
)
