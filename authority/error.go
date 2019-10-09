package authority

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type apiCtx map[string]interface{}

// Error implements the api.Error interface and adds context to error messages.
type apiError struct {
	err     error
	code    int
	context apiCtx
}

// Cause implements the errors.Causer interface and returns the original error.
func (e *apiError) Cause() error {
	return e.err
}

// Error returns an error message with additional context.
func (e *apiError) Error() string {
	ret := e.err.Error()

	/*
		if len(e.context) > 0 {
			ret += "\n\nContext:"
			for k, v := range e.context {
				ret += fmt.Sprintf("\n    %s: %v", k, v)
			}
		}
	*/
	return ret
}

// ErrorResponse represents an error in JSON format.
type ErrorResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// StatusCode returns an http status code indicating the type and severity of
// the error.
func (e *apiError) StatusCode() int {
	if e.code == 0 {
		return http.StatusInternalServerError
	}
	return e.code
}

// MarshalJSON implements json.Marshaller interface for the Error struct.
func (e *apiError) MarshalJSON() ([]byte, error) {
	return json.Marshal(&ErrorResponse{Status: e.code, Message: http.StatusText(e.code)})
}

// UnmarshalJSON implements json.Unmarshaler interface for the Error struct.
func (e *apiError) UnmarshalJSON(data []byte) error {
	var er ErrorResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return err
	}
	e.code = er.Status
	e.err = fmt.Errorf(er.Message)
	return nil
}
