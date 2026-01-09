package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"
)

var clfFields = [...]string{
	"request-id", "remote-address", "name", "user-id", "time", "duration", "method", "path", "protocol", "status", "size",
}

// CommonLogFormat implements the slog.Handler interface it writes slog
// entries using a CLF format prepended by the request-id.
type CommonLogFormat struct {
	output io.Writer
}

// Enabled implements the slog.Handler interface.
func (f *CommonLogFormat) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

// Handle implements the slog.Handler interface. It returns the given
// slog record as a CLF line with the following format:
//
//	<request-id> <remote-address> <name> <user-id> <time> <duration> "<method> <path> <protocol>" <status> <size>
//
// If a field is not known, the hyphen symbol (-) will be used.
func (f *CommonLogFormat) Handle(ctx context.Context, record slog.Record) error {
	data := make([]string, len(clfFields))

	// Extract fields from the record
	fields := make(map[string]interface{})
	record.Attrs(func(attr slog.Attr) bool {
		fields[attr.Key] = attr.Value.Any()
		return true
	})

	for i, name := range clfFields {
		if v, ok := fields[name]; ok {
			switch v := v.(type) {
			case error:
				data[i] = v.Error()
			case string:
				if v == "" {
					data[i] = "-"
				} else {
					data[i] = v
				}
			case time.Time:
				data[i] = v.Format(time.RFC3339)
			case time.Duration:
				data[i] = strconv.FormatInt(int64(v/time.Millisecond), 10)
			case int:
				data[i] = strconv.FormatInt(int64(v), 10)
			case int64:
				data[i] = strconv.FormatInt(v, 10)
			default:
				data[i] = fmt.Sprintf("%v", v)
			}
		} else {
			data[i] = "-"
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

	_, err := f.output.Write(buf.Bytes())
	return err
}

// WithAttrs implements the slog.Handler interface.
func (f *CommonLogFormat) WithAttrs(attrs []slog.Attr) slog.Handler {
	// For simplicity, return the same handler since CLF format
	// doesn't support additional attributes
	return f
}

// WithGroup implements the slog.Handler interface.
func (f *CommonLogFormat) WithGroup(name string) slog.Handler {
	// For simplicity, return the same handler since CLF format
	// doesn't support groups
	return f
}
