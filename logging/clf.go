package logging

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

var clfFields = [...]string{
	"request-id", "remote-address", "name", "user-id", "time", "duration", "method", "path", "protocol", "status", "size",
}

// CommonLogFormat implements the logrus.Formatter interface it writes logrus
// entries using a CLF format prepended by the request-id.
type CommonLogFormat struct{}

// Format implements the logrus.Formatter interface. It returns the given
// logrus entry as a CLF line with the following format:
//
//	<request-id> <remote-address> <name> <user-id> <time> <duration> "<method> <path> <protocol>" <status> <size>
//
// If a field is not known, the hyphen symbol (-) will be used.
func (f *CommonLogFormat) Format(entry *logrus.Entry) ([]byte, error) {
	data := make([]string, len(clfFields))
	for i, name := range clfFields {
		if v, ok := entry.Data[name]; ok {
			switch v := v.(type) {
			case error:
				data[i] = v.Error() //nolint:gosec // i is bounded by len(clfFields)
			case string:
				if v == "" {
					data[i] = "-" //nolint:gosec // i is bounded by len(clfFields)
				} else {
					data[i] = v //nolint:gosec // i is bounded by len(clfFields)
				}
			case time.Time:
				data[i] = v.Format(time.RFC3339) //nolint:gosec // i is bounded by len(clfFields)
			case time.Duration:
				data[i] = strconv.FormatInt(int64(v/time.Millisecond), 10) //nolint:gosec // i is bounded by len(clfFields)
			case int:
				data[i] = strconv.FormatInt(int64(v), 10) //nolint:gosec // i is bounded by len(clfFields)
			case int64:
				data[i] = strconv.FormatInt(v, 10) //nolint:gosec // i is bounded by len(clfFields)
			default:
				data[i] = fmt.Sprintf("%v", v) //nolint:gosec // i is bounded by len(clfFields)
			}
		} else {
			data[i] = "-" //nolint:gosec // i is bounded by len(clfFields)
		}
	}

	var buf bytes.Buffer
	buf.WriteString(data[0])
	buf.WriteByte(' ')
	buf.WriteString(data[1])
	buf.WriteByte(' ')
	buf.WriteString(data[2])
	buf.WriteByte(' ')
	buf.WriteString(data[3])
	buf.WriteByte(' ')
	buf.WriteString(data[4])
	buf.WriteByte(' ')
	buf.WriteString(data[5])
	buf.WriteString(" \"")
	buf.WriteString(data[6])
	buf.WriteByte(' ')
	buf.WriteString(data[7])
	buf.WriteByte(' ')
	buf.WriteString(data[8])
	buf.WriteString("\" ")
	buf.WriteString(data[9])
	buf.WriteByte(' ')
	buf.WriteString(data[10])
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
