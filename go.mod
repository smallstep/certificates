module github.com/smallstep/certificates

go 1.16

require (
	cloud.google.com/go v0.100.2
	cloud.google.com/go/kms v1.4.0
	cloud.google.com/go/security v1.3.0
	github.com/Azure/azure-sdk-for-go v58.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.17
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.8
	github.com/Azure/go-autorest/autorest/date v0.3.0
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2
	github.com/ThalesIgnite/crypto11 v1.2.4
	github.com/aws/aws-sdk-go v1.37.0
	github.com/dgraph-io/ristretto v0.0.4-0.20200906165740-41ebdbffecfd // indirect
	github.com/go-chi/chi v4.0.2+incompatible
	github.com/go-piv/piv-go v1.7.0
	github.com/golang/mock v1.6.0
	github.com/google/go-attestation v0.4.4-0.20220404204839-8820d49b18d9
	github.com/google/go-cmp v0.5.8
	github.com/google/uuid v1.3.0
	github.com/googleapis/gax-go/v2 v2.1.1
	github.com/hashicorp/vault/api v1.3.1
	github.com/hashicorp/vault/api/auth/approle v0.1.1
	github.com/hashicorp/vault/api/auth/kubernetes v0.1.0
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/micromdm/scep/v2 v2.1.0
	github.com/newrelic/go-agent v2.15.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.2.1
	github.com/sirupsen/logrus v1.8.1
	github.com/slackhq/nebula v1.5.2
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/nosql v0.4.0
	github.com/stretchr/testify v1.7.1
	github.com/urfave/cli v1.22.4
	go.mozilla.org/pkcs7 v0.0.0-20210826202110-33d05740a352
	go.step.sm/cli-utils v0.7.0
	go.step.sm/crypto v0.16.2
	go.step.sm/linkedca v0.16.1
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/net v0.0.0-20220403103023-749bd193bc2b
	golang.org/x/sys v0.0.0-20220405052023-b1e9470b6e64 // indirect
	google.golang.org/api v0.70.0
	google.golang.org/genproto v0.0.0-20220401170504-314d38edb7de
	google.golang.org/grpc v1.45.0
	google.golang.org/protobuf v1.28.0
	gopkg.in/square/go-jose.v2 v2.6.0
	gopkg.in/yaml.v3 v3.0.0 // indirect
)

// replace github.com/smallstep/nosql => ../nosql
// replace go.step.sm/crypto => ../crypto
// replace go.step.sm/cli-utils => ../cli-utils
// replace go.step.sm/linkedca => ../linkedca

// use github.com/smallstep/pkcs7 fork with patches applied
replace go.mozilla.org/pkcs7 => github.com/smallstep/pkcs7 v0.0.0-20211016004704-52592125d6f6

replace go.step.sm/crypto => github.com/brandonweeks/crypto v0.16.2-0.20220531234114-45e4f06ca16b

replace github.com/google/go-attestation => github.com/brandonweeks/go-attestation v0.0.0-20220602235615-164122a1d59b
