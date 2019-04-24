// +build ignore

package provisioner

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fullsailor/pkcs7"
	"github.com/smallstep/assert"
)

var rsaCert = `-----BEGIN CERTIFICATE-----
MIIDIjCCAougAwIBAgIJAKnL4UEDMN/FMA0GCSqGSIb3DQEBBQUAMGoxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRgw
FgYDVQQKEw9BbWF6b24uY29tIEluYy4xGjAYBgNVBAMTEWVjMi5hbWF6b25hd3Mu
Y29tMB4XDTE0MDYwNTE0MjgwMloXDTI0MDYwNTE0MjgwMlowajELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxGDAWBgNV
BAoTD0FtYXpvbi5jb20gSW5jLjEaMBgGA1UEAxMRZWMyLmFtYXpvbmF3cy5jb20w
gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIe9GN//SRK2knbjySG0ho3yqQM3
e2TDhWO8D2e8+XZqck754gFSo99AbT2RmXClambI7xsYHZFapbELC4H91ycihvrD
jbST1ZjkLQgga0NE1q43eS68ZeTDccScXQSNivSlzJZS8HJZjgqzBlXjZftjtdJL
XeE4hwvo0sD4f3j9AgMBAAGjgc8wgcwwHQYDVR0OBBYEFCXWzAgVyrbwnFncFFIs
77VBdlE4MIGcBgNVHSMEgZQwgZGAFCXWzAgVyrbwnFncFFIs77VBdlE4oW6kbDBq
MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
dHRsZTEYMBYGA1UEChMPQW1hem9uLmNvbSBJbmMuMRowGAYDVQQDExFlYzIuYW1h
em9uYXdzLmNvbYIJAKnL4UEDMN/FMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEF
BQADgYEAFYcz1OgEhQBXIwIdsgCOS8vEtiJYF+j9uO6jz7VOmJqO+pRlAbRlvY8T
C1haGgSI/A1uZUKs/Zfnph0oEI0/hu1IIJ/SKBDtN5lvmZ/IzbOPIJWirlsllQIQ
7zvWbGd9c9+Rm3p04oTvhup99la7kZqevJK0QRdD/6NpCKsqP/0=
-----END CERTIFICATE-----`

var rsaSig = `eYko51V+DBTE/pLMwqH9tekcIGdIL6jGkgmh0faKQbHUrWVfaw2ffx032iqbEkvbqIMx0I4ewl+Cq5IejPQ5ax4+Nb9gSoMHS8VCjAUkpj9dUXPG2DEvTHukpvUTy8fGn1a/3LS5GdEPnDVkMj2QDHDBGskH4eA46x9c069xeyE=`

var dsaCert = `-----BEGIN CERTIFICATE-----
MIIC7TCCAq0CCQCWukjZ5V4aZzAJBgcqhkjOOAQDMFwxCzAJBgNVBAYTAlVTMRkw
FwYDVQQIExBXYXNoaW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYD
VQQKExdBbWF6b24gV2ViIFNlcnZpY2VzIExMQzAeFw0xMjAxMDUxMjU2MTJaFw0z
ODAxMDUxMjU2MTJaMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNoaW5ndG9u
IFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNl
cnZpY2VzIExMQzCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQCjkvcS2bb1VQ4yt/5e
ih5OO6kK/n1Lzllr7D8ZwtQP8fOEpp5E2ng+D6Ud1Z1gYipr58Kj3nssSNpI6bX3
VyIQzK7wLclnd/YozqNNmgIyZecN7EglK9ITHJLP+x8FtUpt3QbyYXJdmVMegN6P
hviYt5JH/nYl4hh3Pa1HJdskgQIVALVJ3ER11+Ko4tP6nwvHwh6+ERYRAoGBAI1j
k+tkqMVHuAFcvAGKocTgsjJem6/5qomzJuKDmbJNu9Qxw3rAotXau8Qe+MBcJl/U
hhy1KHVpCGl9fueQ2s6IL0CaO/buycU1CiYQk40KNHCcHfNiZbdlx1E9rpUp7bnF
lRa2v1ntMX3caRVDdbtPEWmdxSCYsYFDk4mZrOLBA4GEAAKBgEbmeve5f8LIE/Gf
MNmP9CM5eovQOGx5ho8WqD+aTebs+k2tn92BBPqeZqpWRa5P/+jrdKml1qx4llHW
MXrs3IgIb6+hUIB+S8dz8/mmO0bpr76RoZVCXYab2CZedFut7qc3WUH9+EUAH5mw
vSeDCOUMYQR7R9LINYwouHIziqQYMAkGByqGSM44BAMDLwAwLAIUWXBlk40xTwSw
7HX32MxXYruse9ACFBNGmdX2ZBrVNGrN9N2f6ROk0k9K
-----END CERTIFICATE-----`

var dsaSig = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHTewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4yMy40NyIsCiAgImRldnBheVByb2R1Y3RDb2RlcyIgOiBu
dWxsLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2RlcyIgOiBudWxsLAogICJ2ZXJzaW9uIiA6ICIy
MDE3LTA5LTMwIiwKICAiaW5zdGFuY2VJZCIgOiAiaS0wMmUzYmVjMWY2MDBmNWUzMyIsCiAgImJp
bGxpbmdQcm9kdWN0cyIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAi
YXZhaWxhYmlsaXR5Wm9uZSIgOiAidXMtd2VzdC0xYiIsCiAgImtlcm5lbElkIiA6IG51bGwsCiAg
InJhbWRpc2tJZCIgOiBudWxsLAogICJhY2NvdW50SWQiIDogIjgwNzQ5MjQ3MzI2MyIsCiAgImFy
Y2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1hZ2VJZCIgOiAiYW1pLTFjMWQyMTdjIiwKICAi
cGVuZGluZ1RpbWUiIDogIjIwMTctMTEtMjFUMDA6MjU6MjNaIiwKICAicmVnaW9uIiA6ICJ1cy13
ZXN0LTEiCn0AAAAAAAAxggEYMIIBFAIBATBpMFwxCzAJBgNVBAYTAlVTMRkwFwYDVQQIExBXYXNo
aW5ndG9uIFN0YXRlMRAwDgYDVQQHEwdTZWF0dGxlMSAwHgYDVQQKExdBbWF6b24gV2ViIFNlcnZp
Y2VzIExMQwIJAJa6SNnlXhpnMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0xODA3MzAyMzMxMDRaMCMGCSqGSIb3DQEJBDEWBBQUze548OLd+uOT
aOSTDLlV9mevbTAJBgcqhkjOOAQDBC8wLQIUDGeP44Ge1atMQghe+ENV4IDM0zQCFQCBTOEvfKu+
uscwutj+7RCNgSVaWgAAAAAAAA==`

var doc = `{
  "privateIp" : "172.31.23.47",
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "version" : "2017-09-30",
  "instanceId" : "i-02e3bec1f600f5e33",
  "billingProducts" : null,
  "instanceType" : "t2.micro",
  "availabilityZone" : "us-west-1b",
  "kernelId" : null,
  "ramdiskId" : null,
  "accountId" : "807492473263",
  "architecture" : "x86_64",
  "imageId" : "ami-1c1d217c",
  "pendingTime" : "2017-11-21T00:25:23Z",
  "region" : "us-west-1"
}`

func TestAWSRSA(t *testing.T) {
	block, _ := pem.Decode([]byte(rsaCert))

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	signature, err := base64.StdEncoding.DecodeString(rsaSig)
	assert.FatalError(t, err)

	err = cert.CheckSignature(x509.SHA256WithRSA, []byte(doc), signature)
	assert.FatalError(t, err)
}

func TestAWSDSA(t *testing.T) {
	block, _ := pem.Decode([]byte(dsaCert))

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.FatalError(t, err)

	signature, err := base64.StdEncoding.DecodeString(dsaSig)
	assert.FatalError(t, err)

	p7, err := pkcs7.Parse(signature)
	assert.FatalError(t, err)

	p7.Certificates = append(p7.Certificates, cert)

	assert.FatalError(t, p7.Verify())
}

func TestAWS_GetIdentityToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/document":
			w.Write([]byte(doc))
		case "/signature":
			w.Write([]byte(rsaSig))
		default:
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	config, err := newAWSConfig()
	assert.FatalError(t, err)
	config.identityURL = srv.URL + "/document"
	config.signatureURL = srv.URL + "/signature"

	type fields struct {
		Type    string
		Name    string
		Claims  *Claims
		claimer *Claimer
		config  *awsConfig
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{"ok", fields{"AWS", "name", nil, nil, config}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &AWS{
				Type:    tt.fields.Type,
				Name:    tt.fields.Name,
				Claims:  tt.fields.Claims,
				claimer: tt.fields.claimer,
				config:  tt.fields.config,
			}
			got, err := p.GetIdentityToken()
			if (err != nil) != tt.wantErr {
				t.Errorf("AWS.GetIdentityToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("AWS.GetIdentityToken() = %v, want %v", got, tt.want)
			}
			t.Error(got)
			// parts := strings.Split(got, ".")
			// signed, err := base64.RawURLEncoding.DecodeString(parts[0])
			// assert.FatalError(t, err)
			// signature, err := base64.RawURLEncoding.DecodeString(parts[1])
			// assert.FatalError(t, err)
			// assert.FatalError(t, err, config.certificate.CheckSignature(config.signatureAlgorithm, signed, signature))
		})
	}
}
