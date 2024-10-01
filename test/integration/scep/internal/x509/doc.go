/*
Package legacyx509 is a copy of certain parts of Go's crypto/x509 package.
It is based on Go 1.23, and has just the parts copied over required for
parsing X509 certificates.

The copy in this repository is intended to be used for preparing a SCEP request
emulating a Windows SCEP client. The Windows SCEP client marks the authority
key identifier as critical in the self-signed SCEP enrolment certificate, which
fails to parse using the standard X509 parser in Go 1.23 and later.

This is itself a copy from the copy in our PKCS7 package. We currently don't
intend to maintain that in an importable package, since we only need these copies
for testing purposes, hence needing another copy of the code.
*/
package legacyx509
