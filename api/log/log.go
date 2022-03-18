package log

import (
	"log"
	"net/http"

	"github.com/smallstep/certificates/logging"
)

// Error adds to the response writer the given error if it implements
// logging.ResponseLogger. If it does not implement it, then writes the error
// using the log package.
func Error(rw http.ResponseWriter, err error) {
	if rl, ok := rw.(logging.ResponseLogger); ok {
		rl.WithFields(map[string]interface{}{
			"error": err,
		})
	} else {
		log.Println(err)
	}
}

// EnabledResponse log the response object if it implements the EnableLogger
// interface.
func EnabledResponse(rw http.ResponseWriter, v interface{}) {
	type enableLogger interface {
		ToLog() (interface{}, error)
	}

	if el, ok := v.(enableLogger); ok {
		out, err := el.ToLog()
		if err != nil {
			Error(rw, err)

			return
		}

		if rl, ok := rw.(logging.ResponseLogger); ok {
			rl.WithFields(map[string]interface{}{
				"response": out,
			})
		} else {
			log.Println(out)
		}
	}
}
