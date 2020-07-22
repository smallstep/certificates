{
    "version": 3,
    "subject": "subjectCommonName",
    "issuer": "issuerCommonName",
    "serialNumber": "0x1234567890",
    "dnsNames": "doe.com",
    "emailAddresses": "jane@doe.com",
    "ipAddresses": "127.0.0.1",
    "uris": "https://doe.com",
    "sans": [{"type":"dns", "value":"www.doe.com"}],
    "extensions": [{"id":"1.2.3.4","critical":true,"value":"ZXh0ZW5zaW9u"}],
    "keyUsage": ["digitalSignature"],
    "extKeyUsage": ["serverAuth"],
    "subjectKeyId": "c3ViamVjdEtleUlk",
    "authorityKeyId": "YXV0aG9yaXR5S2V5SWQ=",
    "ocspServer": "https://ocsp.server",
    "issuingCertificateURL": "https://ca.com",
    "crlDistributionPoints": "https://ca.com/ca.crl",
    "policyIdentifiers": "5.6.7.8.9.0",
    "basicConstraints": {
        "isCA": false, 
        "maxPathLen": 0
    },
    "nameConstraints": {
        "critical": true,
        "permittedDNSDomains": "jane.doe.com",
        "excludedDNSDomains": "john.doe.com",
        "permittedIPRanges": "127.0.0.1/32",
        "excludedIPRanges": "0.0.0.0/0",
        "permittedEmailAddresses": "jane@doe.com",
        "excludedEmailAddresses": "john@doe.com",
        "permittedURIDomains": "https://jane.doe.com",
        "excludedURIDomains": "https://john.doe.com"
    },
    "signatureAlgorithm": "Ed25519"
}