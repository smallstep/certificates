package uri

import (
	"net/url"
	"reflect"
	"testing"
)

func TestNew(t *testing.T) {
	type args struct {
		scheme string
		values url.Values
	}
	tests := []struct {
		name string
		args args
		want *URI
	}{
		{"ok", args{"yubikey", url.Values{"slot-id": []string{"9a"}}}, &URI{
			URL:    &url.URL{Scheme: "yubikey", Opaque: "slot-id=9a"},
			Values: url.Values{"slot-id": []string{"9a"}},
		}},
		{"ok multiple", args{"yubikey", url.Values{"slot-id": []string{"9a"}, "foo": []string{"bar"}}}, &URI{
			URL: &url.URL{Scheme: "yubikey", Opaque: "foo=bar;slot-id=9a"},
			Values: url.Values{
				"slot-id": []string{"9a"},
				"foo":     []string{"bar"},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.scheme, tt.args.values); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFile(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want *URI
	}{
		{"ok", args{"/tmp/ca.crt"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.crt"},
			Values: url.Values(nil),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewFile(tt.args.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasScheme(t *testing.T) {
	type args struct {
		scheme string
		rawuri string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"ok", args{"yubikey", "yubikey:slot-id=9a"}, true},
		{"ok empty", args{"yubikey", "yubikey:"}, true},
		{"ok letter case", args{"awsKMS", "AWSkms:key-id=abcdefg?foo=bar"}, true},
		{"fail", args{"yubikey", "awskms:key-id=abcdefg"}, false},
		{"fail parse", args{"yubikey", "yubi%key:slot-id=9a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasScheme(tt.args.scheme, tt.args.rawuri); got != tt.want {
				t.Errorf("HasScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
				t.Errorf("Parse() = %#v, want %v", got.URL, tt.want)
			}
		})
	}
}

func TestParseWithScheme(t *testing.T) {
	type args struct {
		scheme string
		rawuri string
	}
	tests := []struct {
		name    string
		args    args
		want    *URI
		wantErr bool
	}{
		{"ok", args{"yubikey", "yubikey:slot-id=9a"}, &URI{
			URL:    &url.URL{Scheme: "yubikey", Opaque: "slot-id=9a"},
			Values: url.Values{"slot-id": []string{"9a"}},
		}, false},
		{"ok file", args{"file", "file:///tmp/ca.cert"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.cert"},
			Values: url.Values{},
		}, false},
		{"fail parse", args{"yubikey", "yubikey"}, nil, true},
		{"fail scheme", args{"yubikey", "awskms:slot-id=9a"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseWithScheme(tt.args.scheme, tt.args.rawuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWithScheme() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWithScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_Get(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want string
	}{
		{"ok", mustParse("yubikey:slot-id=9a"), args{"slot-id"}, "9a"},
		{"ok first", mustParse("yubikey:slot-id=9a;slot-id=9b"), args{"slot-id"}, "9a"},
		{"ok multiple", mustParse("yubikey:slot-id=9a;foo=bar"), args{"foo"}, "bar"},
		{"fail missing", mustParse("yubikey:slot-id=9a"), args{"foo"}, ""},
		{"fail in query", mustParse("yubikey:slot-id=9a?foo=bar"), args{"foo"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.Get(tt.args.key); got != tt.want {
				t.Errorf("URI.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}
