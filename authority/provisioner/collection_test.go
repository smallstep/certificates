package provisioner

import (
	"reflect"
	"sync"
	"testing"

	"github.com/smallstep/assert"

	"github.com/smallstep/cli/jose"
)

// func Test_newSortedProvisioners(t *testing.T) {
// 	provisioners := make(List, 20)
// 	for i := range provisioners {
// 		provisioners[i] = generateProvisioner(t)
// 	}

// 	ps, err := newSortedProvisioners(provisioners)
// 	assert.FatalError(t, err)
// 	prev := ""
// 	for i, p := range ps {
// 		if p.uid < prev {
// 			t.Errorf("%s should be less that %s", p.uid, prev)
// 		}
// 		if p.provisioner.Key.KeyID != provisioners[i].Key.KeyID {
// 			t.Errorf("provisioner order is not the same: %s != %s", p.provisioner.Key.KeyID, provisioners[i].Key.KeyID)
// 		}
// 		prev = p.uid
// 	}
// }

// func Test_provisionerSlice_Find(t *testing.T) {
// 	trim := func(s string) string {
// 		return strings.TrimLeft(s, "0")
// 	}
// 	provisioners := make([]*Provisioner, 20)
// 	for i := range provisioners {
// 		provisioners[i] = generateProvisioner(t)
// 	}
// 	ps, err := newSortedProvisioners(provisioners)
// 	assert.FatalError(t, err)

// 	type args struct {
// 		cursor string
// 		limit  int
// 	}
// 	tests := []struct {
// 		name  string
// 		p     provisionerSlice
// 		args  args
// 		want  []*JWK
// 		want1 string
// 	}{
// 		{"all", ps, args{"", DefaultProvisionersMax}, provisioners[0:20], ""},
// 		{"0 to 19", ps, args{"", 20}, provisioners[0:20], ""},
// 		{"0 to 9", ps, args{"", 10}, provisioners[0:10], trim(ps[10].uid)},
// 		{"9 to 19", ps, args{trim(ps[10].uid), 10}, provisioners[10:20], ""},
// 		{"1", ps, args{trim(ps[1].uid), 1}, provisioners[1:2], trim(ps[2].uid)},
// 		{"1 to 5", ps, args{trim(ps[1].uid), 4}, provisioners[1:5], trim(ps[5].uid)},
// 		{"defaultLimit", ps, args{"", 0}, provisioners[0:20], ""},
// 		{"overTheLimit", ps, args{"", DefaultProvisionersMax + 1}, provisioners[0:20], ""},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			got, got1 := tt.p.Find(tt.args.cursor, tt.args.limit)
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("provisionerSlice.Find() got = %v, want %v", got, tt.want)
// 			}
// 			if got1 != tt.want1 {
// 				t.Errorf("provisionerSlice.Find() got1 = %v, want %v", got1, tt.want1)
// 			}
// 		})
// 	}
// }

func TestCollection_Load(t *testing.T) {
	p, err := generateJWK()
	assert.FatalError(t, err)
	byID := new(sync.Map)
	byID.Store(p.GetID(), p)
	byID.Store("string", "a-string")

	type fields struct {
		byID *sync.Map
	}
	type args struct {
		id string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   Interface
		want1  bool
	}{
		{"ok", fields{byID}, args{p.GetID()}, p, true},
		{"fail", fields{byID}, args{"fail"}, nil, false},
		{"invalid", fields{byID}, args{"string"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collection{
				byID: tt.fields.byID,
			}
			got, got1 := c.Load(tt.args.id)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Collection.Load() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Collection.Load() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestCollection_LoadByToken(t *testing.T) {
	p1, err := generateJWK()
	assert.FatalError(t, err)
	p2, err := generateJWK()
	assert.FatalError(t, err)
	p3, err := generateOIDC()
	assert.FatalError(t, err)

	byID := new(sync.Map)
	byID.Store(p1.GetID(), p1)
	byID.Store(p2.GetID(), p2)
	byID.Store(p3.GetID(), p3)
	byID.Store("string", "a-string")

	jwk, err := decryptJSONWebKey(p1.EncryptedKey)
	assert.FatalError(t, err)
	token, err := generateSimpleToken(p1.Name, testAudiences[0], jwk)
	assert.FatalError(t, err)
	t1, c1, err := parseToken(token)
	assert.FatalError(t, err)

	jwk, err = decryptJSONWebKey(p2.EncryptedKey)
	token, err = generateSimpleToken(p2.Name, testAudiences[1], jwk)
	assert.FatalError(t, err)
	t2, c2, err := parseToken(token)
	assert.FatalError(t, err)

	token, err = generateSimpleToken(p3.configuration.Issuer, p3.ClientID, &p3.keyStore.keys.Keys[0])
	assert.FatalError(t, err)
	t3, c3, err := parseToken(token)
	assert.FatalError(t, err)

	type fields struct {
		byID      *sync.Map
		audiences []string
	}
	type args struct {
		token  *jose.JSONWebToken
		claims *jose.Claims
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   Interface
		want1  bool
	}{
		{"ok1", fields{byID, testAudiences}, args{t1, c1}, p1, true},
		{"ok2", fields{byID, testAudiences}, args{t2, c2}, p2, true},
		{"ok3", fields{byID, testAudiences}, args{t3, c3}, p3, true},
		{"fail", fields{byID, []string{"https://foo"}}, args{t1, c1}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Collection{
				byID:      tt.fields.byID,
				audiences: tt.fields.audiences,
			}
			got, got1 := c.LoadByToken(tt.args.token, tt.args.claims)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Collection.LoadByToken() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Collection.LoadByToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
