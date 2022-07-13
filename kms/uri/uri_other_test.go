//go:build !go1.19

package uri

import (
	"net/url"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	type args struct {
		rawuri string
	}
	tests := []struct {
		name    string
		args    args
		want    *URI
		wantErr bool
	}{
		{"ok", args{"yubikey:slot-id=9a"}, &URI{
			URL:    &url.URL{Scheme: "yubikey", Opaque: "slot-id=9a"},
			Values: url.Values{"slot-id": []string{"9a"}},
		}, false},
		{"ok schema", args{"cloudkms:"}, &URI{
			URL:    &url.URL{Scheme: "cloudkms"},
			Values: url.Values{},
		}, false},
		{"ok query", args{"yubikey:slot-id=9a;foo=bar?pin=123456&foo=bar"}, &URI{
			URL:    &url.URL{Scheme: "yubikey", Opaque: "slot-id=9a;foo=bar", RawQuery: "pin=123456&foo=bar"},
			Values: url.Values{"slot-id": []string{"9a"}, "foo": []string{"bar"}},
		}, false},
		{"ok file", args{"file:///tmp/ca.cert"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.cert"},
			Values: url.Values{},
		}, false},
		{"ok file simple", args{"file:/tmp/ca.cert"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.cert"},
			Values: url.Values{},
		}, false},
		{"ok file host", args{"file://tmp/ca.cert"}, &URI{
			URL:    &url.URL{Scheme: "file", Host: "tmp", Path: "/ca.cert"},
			Values: url.Values{},
		}, false},
		{"fail schema", args{"cloudkms"}, nil, true},
		{"fail parse", args{"yubi%key:slot-id=9a"}, nil, true},
		{"fail scheme", args{"yubikey"}, nil, true},
		{"fail parse opaque", args{"yubikey:slot-id=%ZZ"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args.rawuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %#v, want %#v", got.URL, tt.want.URL)
			}
		})
	}
}
