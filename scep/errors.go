package scep

// Error is an SCEP error type
type Error struct {
	// Type       ProbType
	// Detail string
	Err    error
	Status int
	// Sub    []*Error
	// Identifier *Identifier
}

// Error implements the error interface.
func (e *Error) Error() string {
	// if e.Err == nil {
	// 	return e.Detail
	// }
	return e.Err.Error()
}
