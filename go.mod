module github.com/smallstep/certificates

go 1.15

require (
	cloud.google.com/go v0.83.0
	github.com/Azure/azure-sdk-for-go v58.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.17
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.8
	github.com/Azure/go-autorest/autorest/date v0.3.0
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/ThalesIgnite/crypto11 v1.2.4
	github.com/aws/aws-sdk-go v1.30.29
	github.com/dgraph-io/ristretto v0.0.4-0.20200906165740-41ebdbffecfd // indirect
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-kit/kit v0.10.0 // indirect
	github.com/go-piv/piv-go v1.7.0
	github.com/golang/mock v1.6.0
	github.com/google/uuid v1.3.0
	github.com/googleapis/gax-go/v2 v2.0.5
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/micromdm/scep/v2 v2.1.0
	github.com/newrelic/go-agent v2.15.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.4.2
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/nosql v0.3.8
	github.com/urfave/cli v1.22.4
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	go.step.sm/cli-utils v0.6.1
	go.step.sm/crypto v0.13.0
	go.step.sm/linkedca v0.7.0
	golang.org/x/crypto v0.0.0-20210915214749-c084706c2272
	golang.org/x/net v0.0.0-20210913180222-943fd674d43e
	google.golang.org/api v0.47.0
	google.golang.org/genproto v0.0.0-20210719143636-1d5a45f8e492
	google.golang.org/grpc v1.39.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/square/go-jose.v2 v2.6.0
)

// avoid license conflict from juju/ansiterm until https://github.com/manifoldco/promptui/pull/181
// is merged or other dependency in path currently in violation fixes compliance
replace github.com/manifoldco/promptui => github.com/nguyer/promptui v0.8.1-0.20210517132806-70ccd4709797

// replace github.com/smallstep/nosql => ../nosql
// replace go.step.sm/crypto => ../crypto
// replace go.step.sm/cli-utils => ../cli-utils
// replace go.step.sm/linkedca => ../linkedca
