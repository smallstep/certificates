//go:build go1.19

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
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.cert", OmitHost: true},
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
		{"ok schema", args{"cloudkms", "cloudkms:"}, &URI{
			URL:    &url.URL{Scheme: "cloudkms"},
			Values: url.Values{},
		}, false},
		{"ok file", args{"file", "file:///tmp/ca.cert"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.cert"},
			Values: url.Values{},
		}, false},
		{"fail parse", args{"yubikey", "yubikey"}, nil, true},
		{"fail scheme", args{"yubikey", "awskms:slot-id=9a"}, nil, true},
		{"fail schema", args{"cloudkms", "cloudkms"}, nil, true},
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
		{"ok in query", mustParse("yubikey:slot-id=9a?foo=bar"), args{"foo"}, "bar"},
		{"fail missing", mustParse("yubikey:slot-id=9a"), args{"foo"}, ""},
		{"fail missing query", mustParse("yubikey:slot-id=9a?bar=zar"), args{"foo"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.Get(tt.args.key); got != tt.want {
				t.Errorf("URI.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_GetBool(t *testing.T) {
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
		want bool
	}{
		{"true", mustParse("azurekms:name=foo;vault=bar;hsm=true"), args{"hsm"}, true},
		{"TRUE", mustParse("azurekms:name=foo;vault=bar;hsm=TRUE"), args{"hsm"}, true},
		{"tRUe query", mustParse("azurekms:name=foo;vault=bar?hsm=tRUe"), args{"hsm"}, true},
		{"false", mustParse("azurekms:name=foo;vault=bar;hsm=false"), args{"hsm"}, false},
		{"false query", mustParse("azurekms:name=foo;vault=bar?hsm=false"), args{"hsm"}, false},
		{"empty", mustParse("azurekms:name=foo;vault=bar;hsm=?bar=true"), args{"hsm"}, false},
		{"missing", mustParse("azurekms:name=foo;vault=bar"), args{"hsm"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.GetBool(tt.args.key); got != tt.want {
				t.Errorf("URI.GetBool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_GetEncoded(t *testing.T) {
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
		want []byte
	}{
		{"ok", mustParse("yubikey:slot-id=9a"), args{"slot-id"}, []byte{0x9a}},
		{"ok first", mustParse("yubikey:slot-id=9a9b;slot-id=9b"), args{"slot-id"}, []byte{0x9a, 0x9b}},
		{"ok percent", mustParse("yubikey:slot-id=9a;foo=%9a%9b%9c"), args{"foo"}, []byte{0x9a, 0x9b, 0x9c}},
		{"ok in query", mustParse("yubikey:slot-id=9a?foo=9a"), args{"foo"}, []byte{0x9a}},
		{"ok in query percent", mustParse("yubikey:slot-id=9a?foo=%9a"), args{"foo"}, []byte{0x9a}},
		{"ok missing", mustParse("yubikey:slot-id=9a"), args{"foo"}, nil},
		{"ok missing query", mustParse("yubikey:slot-id=9a?bar=zar"), args{"foo"}, nil},
		{"ok no hex", mustParse("yubikey:slot-id=09a?bar=zar"), args{"slot-id"}, []byte{'0', '9', 'a'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.uri.GetEncoded(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("URI.GetEncoded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_Pin(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		name string
		uri  *URI
		want string
	}{
		{"from value", mustParse("pkcs11:id=%72%73?pin-value=0123456789"), "0123456789"},
		{"from source", mustParse("pkcs11:id=%72%73?pin-source=testdata/pin.txt"), "trim-this-pin"},
		{"from missing", mustParse("pkcs11:id=%72%73"), ""},
		{"from source missing", mustParse("pkcs11:id=%72%73?pin-source=testdata/foo.txt"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.Pin(); got != tt.want {
				t.Errorf("URI.Pin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_String(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		name string
		uri  *URI
		want string
	}{
		{"ok new", New("yubikey", url.Values{"slot-id": []string{"9a"}, "foo": []string{"bar"}}), "yubikey:foo=bar;slot-id=9a"},
		{"ok parse", mustParse("yubikey:slot-id=9a;foo=bar?bar=zar"), "yubikey:slot-id=9a;foo=bar?bar=zar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.String(); got != tt.want {
				t.Errorf("URI.String() = %v, want %v", got, tt.want)
			}
		})
	}
}
