module github.com/smallstep/certificates

go 1.13

require (
	github.com/Masterminds/sprig/v3 v3.0.0
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/newrelic/go-agent v2.15.0+incompatible
	github.com/pkg/errors v0.8.1
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/smallstep/assert v0.0.0-20200103212524-b99dc1097b15
	github.com/smallstep/cli v0.14.0-rc.3
	github.com/smallstep/nosql v0.2.1-0.20200213174000-bb64e2bbc1bf
	github.com/urfave/cli v1.22.2
	golang.org/x/crypto v0.0.0-20191227163750-53104e6ec876
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553
	gopkg.in/square/go-jose.v2 v2.4.0
)

//replace github.com/smallstep/cli => ../cli
