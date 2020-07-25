package sshutil

import (
	"reflect"
	"testing"
)

func TestCertType_String(t *testing.T) {
	tests := []struct {
		name string
		c    CertType
		want string
	}{
		{"user", UserCert, "user"},
		{"host", HostCert, "host"},
		{"empty", 100, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("CertType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertType_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		c       CertType
		want    []byte
		wantErr bool
	}{
		{"user", UserCert, []byte(`"user"`), false},
		{"host", HostCert, []byte(`"host"`), false},
		{"error", 100, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("CertType.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertType.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertType_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    CertType
		wantErr bool
	}{
		{"user", args{[]byte(`"user"`)}, UserCert, false},
		{"USER", args{[]byte(`"USER"`)}, UserCert, false},
		{"host", args{[]byte(`"host"`)}, HostCert, false},
		{"HosT", args{[]byte(`"HosT"`)}, HostCert, false},
		{" user ", args{[]byte(`" user "`)}, 0, true},
		{"number", args{[]byte(`1`)}, 0, true},
		{"object", args{[]byte(`{}`)}, 0, true},
		{"badJSON", args{[]byte(`"user`)}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ct CertType
			if err := ct.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("CertType.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(ct, tt.want) {
				t.Errorf("CertType.UnmarshalJSON() = %v, want %v", ct, tt.want)
			}
		})
	}
}
