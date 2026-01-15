package logging

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// defaultTraceIdHeader is the default header used as a trace id.
const defaultTraceIDHeader = "X-Smallstep-Id"

// ErrorKey defines the key used to log errors.
const ErrorKey = "error"

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
	name        string
	traceHeader string
	handler     slog.Handler
}

// loggerConfig represents the configuration options for the logger.
type loggerConfig struct {
	Format      string `json:"format"`
	TraceHeader string `json:"traceHeader"`
}

// New initializes the logger with the given options.
func New(name string, raw json.RawMessage) (*Logger, error) {
	var config loggerConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, errors.Wrap(err, "error unmarshalling logging attribute")
	}

	var output io.Writer = os.Stderr
	var handler slog.Handler

	switch strings.ToLower(config.Format) {
	case "", "text":
		_, noColor := os.LookupEnv("NO_COLOR")
		opts := &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}
		if noColor {
			handler = slog.NewTextHandler(output, opts)
		} else {
			handler = slog.NewTextHandler(output, opts)
		}
	case "json":
		opts := &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}
		handler = slog.NewJSONHandler(output, opts)
	case "common":
		handler = &CommonLogFormat{output: output}
	default:
		return nil, errors.Errorf("unsupported logger.format '%s'", config.Format)
	}

	logger := &Logger{
		Logger:      slog.New(handler),
		name:        name,
		traceHeader: config.TraceHeader,
		handler:     handler,
	}
	return logger, nil
}

// GetImpl returns the real implementation of the logger.
func (l *Logger) GetImpl() *slog.Logger {
	return l.Logger
}

// GetTraceHeader returns the trace header configured
func (l *Logger) GetTraceHeader() string {
	if l.traceHeader == "" {
		return defaultTraceIDHeader
	}
	return l.traceHeader
}

// Middleware returns the logger middleware that will trace the request of the
// given handler.
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return NewLoggerHandler(l.name, l, next)
}
