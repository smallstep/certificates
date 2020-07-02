module github.com/smallstep/certificates

go 1.13

require (
	cloud.google.com/go v0.51.0
	github.com/Masterminds/sprig/v3 v3.0.0
	github.com/aws/aws-sdk-go v1.30.29
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-piv/piv-go v1.5.0
	github.com/googleapis/gax-go/v2 v2.0.5
	github.com/juju/ansiterm v0.0.0-20180109212912-720a0952cc2a // indirect
	github.com/lunixbochs/vtclean v1.0.0 // indirect
	github.com/newrelic/go-agent v2.15.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/smallstep/assert v0.0.0-20200103212524-b99dc1097b15
	github.com/smallstep/cli v0.14.6
	github.com/smallstep/nosql v0.3.0
	github.com/urfave/cli v1.22.2
	golang.org/x/crypto v0.0.0-20200323165209-0ec3e9974c59
	golang.org/x/net v0.0.0-20200202094626-16171245cfb2
	google.golang.org/api v0.15.0
	google.golang.org/genproto v0.0.0-20191230161307-f3c370f40bfb
	google.golang.org/grpc v1.26.0
	gopkg.in/square/go-jose.v2 v2.4.0
)

//replace github.com/smallstep/cli => ../cli
//replace github.com/smallstep/nosql => ../nosql
