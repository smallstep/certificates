module github.com/smallstep/certificates

go 1.14

require (
	cloud.google.com/go v0.70.0
	github.com/Masterminds/sprig/v3 v3.1.0
	github.com/ThalesIgnite/crypto11 v1.2.4
	github.com/aws/aws-sdk-go v1.30.29
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-piv/piv-go v1.7.0
	github.com/golang/mock v1.4.4
	github.com/google/uuid v1.1.2
	github.com/googleapis/gax-go/v2 v2.0.5
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/newrelic/go-agent v2.15.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/nosql v0.3.6
	github.com/urfave/cli v1.22.4
	go.step.sm/cli-utils v0.2.0
	go.step.sm/crypto v0.8.0
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
	google.golang.org/api v0.33.0
	google.golang.org/genproto v0.0.0-20201019141844-1ed22bb0c154
	google.golang.org/grpc v1.32.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/square/go-jose.v2 v2.5.1
)

// replace github.com/smallstep/nosql => ../nosql
// replace go.step.sm/crypto => ../crypto
