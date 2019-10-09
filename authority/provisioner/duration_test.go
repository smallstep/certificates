package provisioner

import (
	"reflect"
	"testing"
	"time"
)

func TestNewDuration(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    *Duration
		wantErr bool
	}{
		{"ok", args{"1h2m3s"}, &Duration{Duration: 3723 * time.Second}, false},
		{"fail empty", args{""}, nil, true},
		{"fail number", args{"123"}, nil, true},
		{"fail string", args{"1hour"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDuration(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		d       *Duration
		args    args
		want    *Duration
		wantErr bool
	}{
		{"empty", new(Duration), args{[]byte{}}, new(Duration), true},
		{"bad type", new(Duration), args{[]byte(`15`)}, new(Duration), true},
		{"empty string", new(Duration), args{[]byte(`""`)}, new(Duration), true},
		{"non duration", new(Duration), args{[]byte(`"15"`)}, new(Duration), true},
		{"duration", new(Duration), args{[]byte(`"15m30s"`)}, &Duration{15*time.Minute + 30*time.Second}, false},
		{"nil", nil, args{nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.d.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Duration.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(tt.d, tt.want) {
				t.Errorf("Duration.UnmarshalJSON() = %v, want %v", tt.d, tt.want)
			}
		})
	}
}

func TestDuration_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		d       *Duration
		want    []byte
		wantErr bool
	}{
		{"string", &Duration{15*time.Minute + 30*time.Second}, []byte(`"15m30s"`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.d.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("Duration.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Duration.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDuration_Value(t *testing.T) {
	var dur *Duration
	tests := []struct {
		name     string
		duration *Duration
		want     time.Duration
	}{
		{"ok", &Duration{Duration: 1 * time.Minute}, 1 * time.Minute},
		{"ok new", new(Duration), 0},
		{"ok nil", nil, 0},
		{"ok nil var", dur, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.duration.Value(); got != tt.want {
				t.Errorf("Duration.Value() = %v, want %v", got, tt.want)
			}
		})
	}
}
