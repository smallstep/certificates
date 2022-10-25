package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"go.step.sm/crypto/jose"
	"go.step.sm/linkedca"

	"github.com/smallstep/certificates/cas/apiv1"
)

func TestPKI_WriteHelmTemplate(t *testing.T) {
	var preparePKI = func(t *testing.T, opts ...Option) *PKI {
		o := apiv1.Options{
			Type:      "softcas",
			IsCreator: true,
		}

		// Add default WithHelm option
		opts = append(opts, WithHelm())

		// TODO(hs): invoking `New` doesn't perform all operations that are executed
		// when `ca init --helm` is executed. Ideally this logic should be handled
		// in one place and probably inside of the PKI initialization. For testing
		// purposes the missing operations to fill a Helm template fully are faked
		// by `setKeyPair`, `setCertificates` and `setSSHSigningKeys`
		p, err := New(o, opts...)
		assert.NoError(t, err)

		// setKeyPair sets a predefined JWK and a default JWK provisioner. This is one
		// of the things performed in the `ca init` code that's not part of `New`, but
		// performed after that in p.GenerateKeyPairs`. We're currently using the same
		// JWK for every test to keep test variance small: we're not testing JWK generation
		// here after all. It's a bit dangerous to redefine the function here, but it's
		// the simplest way to make this fully testable without refactoring the init now.
		// The password for the predefined encrypted key is \x01\x03\x03\x07.
		setKeyPair(t, p)

		// setCertificates sets some static intermediate and root CA certificate bytes. It
		// replaces the logic executed in `p.GenerateRootCertificate`, `p.WriteRootCertificate`,
		// and `p.GenerateIntermediateCertificate`.
		setCertificates(t, p)

		// setSSHSigningKeys sets predefined SSH user and host certificate and key bytes.
		// This replaces the logic in `p.GenerateSSHSigningKeys`
		setSSHSigningKeys(t, p)

		return p
	}
	type test struct {
		pki      *PKI
		testFile string
		wantErr  bool
	}
	var tests = map[string]func(t *testing.T) test{
		"ok/simple": func(t *testing.T) test {
			return test{
				pki:      preparePKI(t),
				testFile: "testdata/helm/simple.yml",
				wantErr:  false,
			}
		},
		"ok/with-provisioner": func(t *testing.T) test {
			return test{
				pki:      preparePKI(t, WithProvisioner("a-provisioner")),
				testFile: "testdata/helm/with-provisioner.yml",
				wantErr:  false,
			}
		},
		"ok/with-acme": func(t *testing.T) test {
			return test{
				pki:      preparePKI(t, WithACME()),
				testFile: "testdata/helm/with-acme.yml",
				wantErr:  false,
			}
		},
		"ok/with-admin": func(t *testing.T) test {
			return test{
				pki:      preparePKI(t, WithAdmin()),
				testFile: "testdata/helm/with-admin.yml",
				wantErr:  false,
			}
		},
		"ok/with-ssh": func(t *testing.T) test {
			return test{
				pki:      preparePKI(t, WithSSH()),
				testFile: "testdata/helm/with-ssh.yml",
				wantErr:  false,
			}
		},
		"ok/with-ssh-and-acme": func(t *testing.T) test {
			return test{
				pki:      preparePKI(t, WithSSH(), WithACME()),
				testFile: "testdata/helm/with-ssh-and-acme.yml",
				wantErr:  false,
			}
		},
		"fail/authority.ProvisionerToCertificates": func(t *testing.T) test {
			pki := preparePKI(t)
			pki.Authority.Provisioners = append(pki.Authority.Provisioners,
				&linkedca.Provisioner{
					Type:    linkedca.Provisioner_JWK,
					Name:    "Broken JWK",
					Details: nil,
				},
			)
			return test{
				pki:     pki,
				wantErr: true,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {

			w := &bytes.Buffer{}
			if err := tc.pki.WriteHelmTemplate(w); (err != nil) != tc.wantErr {
				t.Errorf("PKI.WriteHelmTemplate() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr {
				// don't compare output if an error was expected on output
				return
			}

			wantBytes, err := os.ReadFile(tc.testFile)
			assert.NoError(t, err)
			if diff := cmp.Diff(wantBytes, w.Bytes()); diff != "" {
				t.Logf("Generated Helm template did not match reference %q\n", tc.testFile)
				t.Errorf("Diff follows:\n%s\n", diff)
				t.Errorf("Full output:\n%s\n", w.Bytes())
			}
		})
	}
}

// setKeyPair sets a predefined JWK and a default JWK provisioner.
func setKeyPair(t *testing.T, p *PKI) {
	t.Helper()

	var err error

	p.ottPublicKey, err = jose.ParseKey([]byte(`{"use":"sig","kty":"EC","kid":"zsUmysmDVoGJ71YoPHyZ-68tNihDaDaO5Mu7xX3M-_I","crv":"P-256","alg":"ES256","x":"Pqnua4CzqKz6ua41J3yeWZ1sRkGt0UlCkbHv8H2DGuY","y":"UhoZ_2ItDen9KQTcjay-ph-SBXH0mwqhHyvrrqIFDOI"}`))
	if err != nil {
		t.Fatal(err)
	}

	p.ottPrivateKey, err = jose.ParseEncrypted("eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiZjVvdGVRS2hvOXl4MmQtSGlMZi05QSJ9.eYA6tt3fNuUpoxKWDT7P0Lbn2juxhEbTxEnwEMbjlYLLQ3sxL-dYTA.ven-FhmdjlC9itH0.a2jRTarN9vPd6F_mWnNBlOn6KbfMjCApmci2t65XbAsLzYFzhI_79Ykm5ueMYTupWLTjBJctl-g51ZHmsSB55pStbpoyyLNAsUX2E1fTmHe-Ni8bRrspwLv15FoN1Xo1g0mpR-ufWIFxOsW-QIfnMmMIIkygVuHFXmg2tFpzTNNG5aS29K3dN2nyk0WJrdIq79hZSTqVkkBU25Yu3A46sgjcM86XcIJJ2XUEih_KWEa6T1YrkixGu96pebjVqbO0R6dbDckfPF7FqNnwPHVtb1ACFpEYoOJVIbUCMaARBpWsxYhjJZlEM__XA46l8snFQDkNY3CdN0p1_gF3ckA.JLmq9nmu1h9oUi1S8ZxYjA")
	if err != nil {
		t.Fatal(err)
	}

	var claims *linkedca.Claims
	if p.options.enableSSH {
		claims = &linkedca.Claims{
			Ssh: &linkedca.SSHClaims{
				Enabled: true,
			},
		}
	}

	publicKey, err := json.Marshal(p.ottPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptedKey, err := p.ottPrivateKey.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	p.Authority.Provisioners = append(p.Authority.Provisioners, &linkedca.Provisioner{
		Type:   linkedca.Provisioner_JWK,
		Name:   p.options.provisioner,
		Claims: claims,
		Details: &linkedca.ProvisionerDetails{
			Data: &linkedca.ProvisionerDetails_JWK{
				JWK: &linkedca.JWKProvisioner{
					PublicKey:           publicKey,
					EncryptedPrivateKey: []byte(encryptedKey),
				},
			},
		},
	})
}

// setCertificates sets some static, gibberish intermediate and root CA certificate and key bytes.
func setCertificates(t *testing.T, p *PKI) {
	raw := []byte("these are just some fake root CA cert bytes")
	p.Files[p.Root[0]] = encodeCertificate(&x509.Certificate{Raw: raw})
	p.Files[p.RootKey[0]] = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("these are just some fake root CA key bytes"),
	})
	p.Files[p.Intermediate] = encodeCertificate(&x509.Certificate{Raw: []byte("these are just some fake intermediate CA cert bytes")})
	p.Files[p.IntermediateKey] = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("these are just some fake intermediate CA key bytes"),
	})
	sum := sha256.Sum256(raw)
	p.Defaults.Fingerprint = strings.ToLower(hex.EncodeToString(sum[:]))
}

// setSSHSigningKeys sets some static, gibberish ssh user and host CA certificate and key bytes.
func setSSHSigningKeys(t *testing.T, p *PKI) {

	if !p.options.enableSSH {
		return
	}

	p.Files[p.Ssh.HostKey] = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("fake ssh host key bytes"),
	})
	p.Files[p.Ssh.HostPublicKey] = []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ0IdS5sZm6KITBMZLEJD6b5ROVraYHcAOr3feFel8r1Wp4DRPR1oU0W00J/zjNBRBbANlJoYN4x/8WNNVZ49Ms=")
	p.Files[p.Ssh.UserKey] = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("fake ssh user key bytes"),
	})
	p.Files[p.Ssh.UserPublicKey] = []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEWA1qUxaGwVNErsvEOGe2d6TvLMF+aiVpuOiIEvpMJ3JeJmecLQctjWqeIbpSvy6/gRa7c82Ge5rLlapYmOChs=")
}
