package x509util

import (
	"encoding/asn1"
	"encoding/json"
	"net"
	"net/url"
	"reflect"
	"testing"
)

func TestMultiString_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		m       MultiString
		want    []byte
		wantErr bool
	}{
		{"ok", []string{"foo", "bar"}, []byte(`["foo","bar"]`), false},
		{"empty", []string{}, []byte(`[]`), false},
		{"nil", nil, []byte(`null`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.m)
			if (err != nil) != tt.wantErr {
				t.Errorf("MultiIPNet.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiIPNet.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiString_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    MultiString
		wantErr bool
	}{
		{"string", args{[]byte(`"foo"`)}, []string{"foo"}, false},
		{"array", args{[]byte(`["foo", "bar", "zar"]`)}, []string{"foo", "bar", "zar"}, false},
		{"empty", args{[]byte(`[]`)}, []string{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`["foo"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got MultiString
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("MultiString.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiString.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiIP_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		m       MultiIP
		want    []byte
		wantErr bool
	}{
		{"ok", []net.IP{net.ParseIP("::1"), net.ParseIP("1.2.3.4")}, []byte(`["::1","1.2.3.4"]`), false},
		{"empty", []net.IP{}, []byte(`[]`), false},
		{"nil", nil, []byte(`null`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.m)
			if (err != nil) != tt.wantErr {
				t.Errorf("MultiIPNet.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiIPNet.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiIP_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    MultiIP
		wantErr bool
	}{
		{"string", args{[]byte(`"::1"`)}, []net.IP{net.ParseIP("::1")}, false},
		{"array", args{[]byte(`["127.0.0.1", "::1"]`)}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, false},
		{"empty", args{[]byte(`[]`)}, []net.IP{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`"foo.bar"`)}, nil, true},
		{"failJSON", args{[]byte(`["::1"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got MultiIP
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("MultiIP.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiIP.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiIPNet_MarshalJSON(t *testing.T) {
	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}

	tests := []struct {
		name    string
		m       MultiIPNet
		want    []byte
		wantErr bool
	}{
		{"ok", []*net.IPNet{ipNet("1.1.0.0/16"), ipNet("2001:db8:8a2e:7334::/64")}, []byte(`["1.1.0.0/16","2001:db8:8a2e:7334::/64"]`), false},
		{"empty", []*net.IPNet{}, []byte(`[]`), false},
		{"nil", nil, []byte(`null`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MultiIPNet.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiIPNet.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiIPNet_UnmarshalJSON(t *testing.T) {
	ipNet := func(s string) *net.IPNet {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return ipNet
	}

	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    MultiIPNet
		wantErr bool
	}{
		{"string", args{[]byte(`"1.1.0.0/16"`)}, []*net.IPNet{ipNet("1.1.0.0/16")}, false},
		{"array", args{[]byte(`["1.0.0.0/24", "2.1.0.0/16"]`)}, []*net.IPNet{ipNet("1.0.0.0/24"), ipNet("2.1.0.0/16")}, false},
		{"empty", args{[]byte(`[]`)}, []*net.IPNet{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`"foo.bar/16"`)}, nil, true},
		{"failJSON", args{[]byte(`["1.0.0.0/24"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got MultiIPNet
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("MultiIPNet.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiIPNet.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiURL_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		m       MultiURL
		want    []byte
		wantErr bool
	}{
		{"ok", []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}, {Scheme: "uri", Opaque: "foo:bar"}}, []byte(`["https://iss#sub","uri:foo:bar"]`), false},
		{"empty", []*url.URL{}, []byte(`[]`), false},
		{"nil", nil, []byte(`null`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MultiURL.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiURL.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiURL_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    MultiURL
		wantErr bool
	}{
		{"string", args{[]byte(`"https://iss#sub"`)}, []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}}, false},
		{"array", args{[]byte(`["https://iss#sub", "uri:foo:bar"]`)}, []*url.URL{{Scheme: "https", Host: "iss", Fragment: "sub"}, {Scheme: "uri", Opaque: "foo:bar"}}, false},
		{"empty", args{[]byte(`[]`)}, []*url.URL{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`":foo:bar"`)}, nil, true},
		{"failJSON", args{[]byte(`["https://iss#sub"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got MultiURL
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("MultiURL.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiURL.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiObjectIdentifier_MarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		m       MultiObjectIdentifier
		want    []byte
		wantErr bool
	}{
		{"ok", []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}, []int{5, 6, 7, 8, 9, 0}}, []byte(`["1.2.3.4","5.6.7.8.9.0"]`), false},
		{"empty", []asn1.ObjectIdentifier{}, []byte(`[]`), false},
		{"nil", nil, []byte(`null`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.m)
			if (err != nil) != tt.wantErr {
				t.Errorf("MultiObjectIdentifier.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiObjectIdentifier.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMultiObjectIdentifier_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    MultiObjectIdentifier
		wantErr bool
	}{
		{"string", args{[]byte(`"1.2.3.4"`)}, []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}}, false},
		{"array", args{[]byte(`["1.2.3.4", "5.6.7.8.9.0"]`)}, []asn1.ObjectIdentifier{[]int{1, 2, 3, 4}, []int{5, 6, 7, 8, 9, 0}}, false},
		{"empty", args{[]byte(`[]`)}, []asn1.ObjectIdentifier{}, false},
		{"null", args{[]byte(`null`)}, nil, false},
		{"fail", args{[]byte(`":foo:bar"`)}, nil, true},
		{"failJSON", args{[]byte(`["https://iss#sub"`)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got MultiObjectIdentifier
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("MultiObjectIdentifier.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MultiObjectIdentifier.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}
