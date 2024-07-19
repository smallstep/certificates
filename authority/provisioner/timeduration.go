package provisioner

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

var now = func() time.Time {
	return time.Now().UTC()
}

// timeOr returns the first of its arguments that is not equal to the zero time.
// This method can be replaced with cmp.Or when step-ca requires Go 1.22.
func timeOr(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// TimeDuration is a type that represents a time but the JSON unmarshaling can
// use a time using the RFC 3339 format or a time.Duration string. If a duration
// is used, the time will be set on the first call to TimeDuration.Time.
type TimeDuration struct {
	t time.Time
	d time.Duration
}

// NewTimeDuration returns a TimeDuration with the defined time.
func NewTimeDuration(t time.Time) TimeDuration {
	return TimeDuration{t: t}
}

// ParseTimeDuration returns a new TimeDuration parsing the RFC 3339 time or
// time.Duration string.
func ParseTimeDuration(s string) (TimeDuration, error) {
	if s == "" {
		return TimeDuration{}, nil
	}

	// Try to use the unquoted RFC 3339 format
	var t time.Time
	if err := t.UnmarshalText([]byte(s)); err == nil {
		return TimeDuration{t: t.UTC()}, nil
	}

	// Try to use the time.Duration string format
	if d, err := time.ParseDuration(s); err == nil {
		return TimeDuration{d: d}, nil
	}

	return TimeDuration{}, errors.Errorf("failed to parse %s", s)
}

// SetDuration initializes the TimeDuration with the given duration string. If
// the time was set it will re-set to zero.
func (t *TimeDuration) SetDuration(d time.Duration) {
	t.t, t.d = time.Time{}, d
}

// SetTime initializes the TimeDuration with the given time. If the duration is
// set it will be re-set to zero.
func (t *TimeDuration) SetTime(tt time.Time) {
	t.t, t.d = tt, 0
}

// IsZero returns true the TimeDuration represents the zero value, false
// otherwise.
func (t *TimeDuration) IsZero() bool {
	return t.t.IsZero() && t.d == 0
}

// Equal returns if t and other are equal.
func (t *TimeDuration) Equal(other *TimeDuration) bool {
	return t.t.Equal(other.t) && t.d == other.d
}

// MarshalJSON implements the json.Marshaler interface. If the time is set it
// will return the time in RFC 3339 format if not it will return the duration
// string.
func (t TimeDuration) MarshalJSON() ([]byte, error) {
	switch {
	case t.t.IsZero():
		if t.d == 0 {
			return []byte(`""`), nil
		}
		return json.Marshal(t.d.String())
	default:
		return t.t.MarshalJSON()
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface. The time is expected
// to be a quoted string in RFC 3339 format or a quoted time.Duration string.
func (t *TimeDuration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.Wrapf(err, "error unmarshaling %s", data)
	}

	// Empty TimeDuration
	if s == "" {
		*t = TimeDuration{}
		return nil
	}

	// Try to use the unquoted RFC 3339 format
	var tt time.Time
	if err := tt.UnmarshalText([]byte(s)); err == nil {
		*t = TimeDuration{t: tt}
		return nil
	}

	// Try to use the time.Duration string format
	if d, err := time.ParseDuration(s); err == nil {
		*t = TimeDuration{d: d}
		return nil
	}

	return errors.Errorf("failed to parse %s", data)
}

// Time calculates the time if needed and returns it.
func (t *TimeDuration) Time() time.Time {
	return t.RelativeTime(now())
}

// Unix calculates the time if needed it and returns the Unix time in seconds.
func (t *TimeDuration) Unix() int64 {
	return t.RelativeTime(now()).Unix()
}

// RelativeTime returns the embedded time.Time or the base time plus the
// duration if this is not zero.
func (t *TimeDuration) RelativeTime(base time.Time) time.Time {
	switch {
	case t == nil:
		return time.Time{}
	case t.t.IsZero():
		if t.d == 0 {
			return time.Time{}
		}
		t.t = base.Add(t.d)
		return t.t.UTC()
	default:
		return t.t.UTC()
	}
}

// String implements the fmt.Stringer interface.
func (t *TimeDuration) String() string {
	return t.Time().String()
}
