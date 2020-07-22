package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"
)

func TestName_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Name
		wantErr bool
	}{
		{"null", args{[]byte("null")}, Name{}, false},
		{"empty", args{[]byte("{}")}, Name{}, false},
		{"commonName", args{[]byte(`"commonName"`)}, Name{CommonName: "commonName"}, false},
		{"object", args{[]byte(`{
			"country": "The country",
			"organization": "The organization",
			"organizationalUnit": ["The organizationalUnit 1", "The organizationalUnit 2"],
			"locality": ["The locality 1", "The locality 2"],
			"province": "The province",
			"streetAddress": "The streetAddress",
			"postalCode": "The postalCode",
			"serialNumber": "The serialNumber",
			"commonName": "The commonName"
		}`)}, Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, false},
		{"number", args{[]byte("1234")}, Name{}, true},
		{"badJSON", args{[]byte("'badJSON'")}, Name{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Name
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Name.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Name.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newSubject(t *testing.T) {
	type args struct {
		n pkix.Name
	}
	tests := []struct {
		name string
		args args
		want Subject
	}{
		{"ok", args{pkix.Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}}, Subject{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newSubject(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubject_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Subject
		wantErr bool
	}{
		{"null", args{[]byte("null")}, Subject{}, false},
		{"empty", args{[]byte("{}")}, Subject{}, false},
		{"commonName", args{[]byte(`"commonName"`)}, Subject{CommonName: "commonName"}, false},
		{"object", args{[]byte(`{
			"country": "The country",
			"organization": "The organization",
			"organizationalUnit": ["The organizationalUnit 1", "The organizationalUnit 2"],
			"locality": ["The locality 1", "The locality 2"],
			"province": "The province",
			"streetAddress": "The streetAddress",
			"postalCode": "The postalCode",
			"serialNumber": "The serialNumber",
			"commonName": "The commonName"
		}`)}, Subject{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, false},
		{"number", args{[]byte("1234")}, Subject{}, true},
		{"badJSON", args{[]byte("'badJSON'")}, Subject{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Subject
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Subject.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Subject.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubject_Set(t *testing.T) {
	type fields struct {
		Country            MultiString
		Organization       MultiString
		OrganizationalUnit MultiString
		Locality           MultiString
		Province           MultiString
		StreetAddress      MultiString
		PostalCode         MultiString
		SerialNumber       string
		CommonName         string
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Subject: pkix.Name{
				Country:            []string{"The country"},
				Organization:       []string{"The organization"},
				OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
				Locality:           []string{"The locality 1", "The locality 2"},
				Province:           []string{"The province"},
				StreetAddress:      []string{"The streetAddress"},
				PostalCode:         []string{"The postalCode"},
				SerialNumber:       "The serialNumber",
				CommonName:         "The commonName",
			},
		}},
		{"overwrite", fields{
			CommonName: "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "The commonName",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Subject{
				Country:            tt.fields.Country,
				Organization:       tt.fields.Organization,
				OrganizationalUnit: tt.fields.OrganizationalUnit,
				Locality:           tt.fields.Locality,
				Province:           tt.fields.Province,
				StreetAddress:      tt.fields.StreetAddress,
				PostalCode:         tt.fields.PostalCode,
				SerialNumber:       tt.fields.SerialNumber,
				CommonName:         tt.fields.CommonName,
			}
			s.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("Subject.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func Test_newIssuer(t *testing.T) {
	type args struct {
		n pkix.Name
	}
	tests := []struct {
		name string
		args args
		want Issuer
	}{
		{"ok", args{pkix.Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}}, Issuer{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newIssuer(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newIssuer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssuer_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Issuer
		wantErr bool
	}{
		{"null", args{[]byte("null")}, Issuer{}, false},
		{"empty", args{[]byte("{}")}, Issuer{}, false},
		{"commonName", args{[]byte(`"commonName"`)}, Issuer{CommonName: "commonName"}, false},
		{"object", args{[]byte(`{
			"country": "The country",
			"organization": "The organization",
			"organizationalUnit": ["The organizationalUnit 1", "The organizationalUnit 2"],
			"locality": ["The locality 1", "The locality 2"],
			"province": "The province",
			"streetAddress": "The streetAddress",
			"postalCode": "The postalCode",
			"serialNumber": "The serialNumber",
			"commonName": "The commonName"
		}`)}, Issuer{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, false},
		{"number", args{[]byte("1234")}, Issuer{}, true},
		{"badJSON", args{[]byte("'badJSON'")}, Issuer{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Issuer
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Issuer.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Issuer.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssuer_Set(t *testing.T) {
	type fields struct {
		Country            MultiString
		Organization       MultiString
		OrganizationalUnit MultiString
		Locality           MultiString
		Province           MultiString
		StreetAddress      MultiString
		PostalCode         MultiString
		SerialNumber       string
		CommonName         string
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Issuer: pkix.Name{
				Country:            []string{"The country"},
				Organization:       []string{"The organization"},
				OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
				Locality:           []string{"The locality 1", "The locality 2"},
				Province:           []string{"The province"},
				StreetAddress:      []string{"The streetAddress"},
				PostalCode:         []string{"The postalCode"},
				SerialNumber:       "The serialNumber",
				CommonName:         "The commonName",
			},
		}},
		{"overwrite", fields{
			CommonName: "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "The commonName",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := Issuer{
				Country:            tt.fields.Country,
				Organization:       tt.fields.Organization,
				OrganizationalUnit: tt.fields.OrganizationalUnit,
				Locality:           tt.fields.Locality,
				Province:           tt.fields.Province,
				StreetAddress:      tt.fields.StreetAddress,
				PostalCode:         tt.fields.PostalCode,
				SerialNumber:       tt.fields.SerialNumber,
				CommonName:         tt.fields.CommonName,
			}
			i.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("Issuer.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}
