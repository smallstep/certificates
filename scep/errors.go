package scep

// Error is an SCEP error type
type Error struct {
	Message string `json:"message"`
	Status  int    `json:"-"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Message
}
