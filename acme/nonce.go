package acme

// Nonce represents an ACME nonce type.
type Nonce string

// String implements the ToString interface.
func (n Nonce) String() string {
	return string(n)
}
