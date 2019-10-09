package provisioner

import (
	"reflect"
	"testing"
	"time"
)

func mockNow() (time.Time, func()) {
	tm := time.Unix(1584198566, 535897000).UTC()
	nowFn := now
	now = func() time.Time {
		return tm
	}
	return tm, func() {
		now = nowFn
	}
}

func TestNewTimeDuration(t *testing.T) {
	tm := time.Unix(1584198566, 535897000).UTC()
	type args struct {
		t time.Time
	}
	tests := []struct {
		name string
		args args
		want TimeDuration
	}{
		{"ok", args{tm}, TimeDuration{t: tm}},
		{"zero", args{time.Time{}}, TimeDuration{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewTimeDuration(tt.args.t); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewTimeDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTimeDuration(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    TimeDuration
		wantErr bool
	}{
		{"timestamp", args{"2020-03-14T15:09:26.535897Z"}, TimeDuration{t: time.Unix(1584198566, 535897000).UTC()}, false},
		{"timestamp", args{"2020-03-14T15:09:26Z"}, TimeDuration{t: time.Unix(1584198566, 0).UTC()}, false},
		{"timestamp", args{"2020-03-14T15:09:26.535897-07:00"}, TimeDuration{t: time.Unix(1584223766, 535897000).UTC()}, false},
		{"timestamp", args{"2020-03-14T15:09:26-07:00"}, TimeDuration{t: time.Unix(1584223766, 0).UTC()}, false},
		{"timestamp", args{"2020-03-14T15:09:26.535897+07:00"}, TimeDuration{t: time.Unix(1584173366, 535897000).UTC()}, false},
		{"timestamp", args{"2020-03-14T15:09:26+07:00"}, TimeDuration{t: time.Unix(1584173366, 0).UTC()}, false},
		{"1h", args{"1h"}, TimeDuration{d: 1 * time.Hour}, false},
		{"-24h60m60s", args{"-24h60m60s"}, TimeDuration{d: -24*time.Hour - 60*time.Minute - 60*time.Second}, false},
		{"0", args{"0"}, TimeDuration{}, false},
		{"empty", args{""}, TimeDuration{}, false},
		{"fail", args{"2020-03-14T15:09:26Z07:00"}, TimeDuration{}, true},
		{"fail", args{"1d"}, TimeDuration{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTimeDuration(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTimeDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTimeDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTimeDuration_SetDuration(t *testing.T) {
	type fields struct {
		t time.Time
		d time.Duration
	}
	type args struct {
		d time.Duration
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *TimeDuration
	}{
		{"new", fields{}, args{2 * time.Hour}, &TimeDuration{d: 2 * time.Hour}},
		{"old", fields{time.Now(), 1 * time.Hour}, args{2 * time.Hour}, &TimeDuration{d: 2 * time.Hour}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := &TimeDuration{
				t: tt.fields.t,
				d: tt.fields.d,
			}
			td.SetDuration(tt.args.d)
			if !reflect.DeepEqual(td, tt.want) {
				t.Errorf("SetDuration() = %v, want %v", td, tt.want)
			}
		})
	}
}

func TestTimeDuration_SetTime(t *testing.T) {
	tm := time.Unix(1584198566, 535897000).UTC()

	type fields struct {
		t time.Time
		d time.Duration
	}
	type args struct {
		tt time.Time
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *TimeDuration
	}{
		{"new", fields{}, args{tm}, &TimeDuration{t: tm}},
		{"old", fields{time.Now(), 1 * time.Hour}, args{tm}, &TimeDuration{t: tm}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := &TimeDuration{
				t: tt.fields.t,
				d: tt.fields.d,
			}
			td.SetTime(tt.args.tt)
			if !reflect.DeepEqual(td, tt.want) {
				t.Errorf("SetTime() = %v, want %v", td, tt.want)
			}
		})
	}
}

func TestTimeDuration_MarshalJSON(t *testing.T) {
	tm := time.Unix(1584198566, 535897000).UTC()
	tests := []struct {
		name         string
		timeDuration TimeDuration
		want         []byte
		wantErr      bool
	}{
		{"empty", TimeDuration{}, []byte(`""`), false},
		{"timestamp", TimeDuration{t: tm}, []byte(`"2020-03-14T15:09:26.535897Z"`), false},
		{"duration", TimeDuration{d: 1 * time.Hour}, []byte(`"1h0m0s"`), false},
		{"fail", TimeDuration{t: time.Date(-1, 0, 0, 0, 0, 0, 0, time.UTC)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.timeDuration.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("TimeDuration.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TimeDuration.MarshalJSON() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTimeDuration_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *TimeDuration
		wantErr bool
	}{
		{"empty", args{[]byte(`""`)}, &TimeDuration{}, false},
		{"timestamp", args{[]byte(`"2020-03-14T15:09:26.535897Z"`)}, &TimeDuration{t: time.Unix(1584198566, 535897000).UTC()}, false},
		{"duration", args{[]byte(`"1h"`)}, &TimeDuration{d: time.Hour}, false},
		{"fail", args{[]byte("123")}, &TimeDuration{}, true},
		{"fail", args{[]byte(`"2020-03-14T15:09:26.535897Z07:00"`)}, &TimeDuration{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := &TimeDuration{}
			if err := td.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("TimeDuration.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(td, tt.want) {
				t.Errorf("TimeDuration.UnmarshalJSON() = %s, want %s", td, tt.want)
			}
		})
	}
}

func TestTimeDuration_Time(t *testing.T) {
	tm, fn := mockNow()
	defer fn()
	tests := []struct {
		name         string
		timeDuration *TimeDuration
		want         time.Time
	}{
		{"zero", nil, time.Time{}},
		{"zero", &TimeDuration{}, time.Time{}},
		{"timestamp", &TimeDuration{t: tm}, tm},
		{"local", &TimeDuration{t: tm.Local()}, tm},
		{"duration", &TimeDuration{d: 1 * time.Hour}, tm.Add(1 * time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.timeDuration.Time()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TimeDuration.Time() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTimeDuration_Unix(t *testing.T) {
	tm, fn := mockNow()
	defer fn()
	tests := []struct {
		name         string
		timeDuration *TimeDuration
		want         int64
	}{
		{"zero", nil, -62135596800},
		{"zero", &TimeDuration{}, -62135596800},
		{"timestamp", &TimeDuration{t: tm}, 1584198566},
		{"local", &TimeDuration{t: tm.Local()}, 1584198566},
		{"duration", &TimeDuration{d: 1 * time.Hour}, 1584202166},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.timeDuration.Unix()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TimeDuration.Unix() = %v, want %v", got, tt.want)

			}
		})
	}
}

func TestTimeDuration_String(t *testing.T) {
	tm, fn := mockNow()
	defer fn()
	tests := []struct {
		name         string
		timeDuration *TimeDuration
		want         string
	}{
		{"zero", nil, "0001-01-01 00:00:00 +0000 UTC"},
		{"zero", &TimeDuration{}, "0001-01-01 00:00:00 +0000 UTC"},
		{"timestamp", &TimeDuration{t: tm}, "2020-03-14 15:09:26.535897 +0000 UTC"},
		{"duration", &TimeDuration{d: 1 * time.Hour}, "2020-03-14 16:09:26.535897 +0000 UTC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeDuration.String(); got != tt.want {
				t.Errorf("TimeDuration.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
