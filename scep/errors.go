package scep

// Error is an SCEP error type
type Error struct {
	// Type       ProbType
	// Detail string
	Message string `json:"message"`
	Status  int    `json:"-"`
	// Sub    []*Error
	// Identifier *Identifier
}

// Error implements the error interface.
func (e *Error) Error() string {
	// if e.Err == nil {
	// 	return e.Detail
	// }
	return e.Message
}
