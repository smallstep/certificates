# Agiligo Development Guide

This fork of step-ca uses the [Agiligo Go variant](https://github.com/ISRI-PQC/agiligo) to explore post-quantum cryptographic support. Agiligo is a modified version of the Go toolchain that adds cryptographic agility features, allowing the use of post-quantum algorithms not yet available in mainline Go.

## Quick Start

**This project requires Docker Compose** - the Agiligo Go toolchain is built and configured automatically inside a container. All development must be done in the container environment.

### Starting the Development Environment

```bash
# From project root - start the container
docker compose run --rm dev

# Inside container - verify setup
go version       # Should show Agiligo-based Go
go env GOROOT    # Should show /usr/local/agiligo
claude --version # Claude Code is pre-installed

# Initialize git submodules (automatically done on first run)
git submodule update --init --recursive

# Start Claude Code for AI assistance
claude

# Build step-ca
make build

# Run tests
make test
```

## Current Status

### What Works ✅
- Docker development environment with Agiligo
- Build system configured
- `go.step.sm/crypto` submodule added at `./crypto-agiligo` (branch: `agiligo-pqc`)
- **Compatibility layer created** (`crypto-agiligo/x509compat/`)
  - Provides old x509 API names that delegate to new Agiligo locations
  - 100% test pass rate
  - Successfully updated `pemutil` to use compatibility layer

### What's Blocked ❌
- **step-ca cannot build** - Third-party dependencies use old x509 API
- **28/42 crypto packages fail** - External dependencies in `/go/pkg/mod/` cannot be patched
- **Critical packages affected**: jose, keyutil, x509util, all KMS providers

### Build Metrics
- **x509compat package**: 1/1 packages (100%) ✅
- **crypto-agiligo**: 14/42 packages (33.3%) - Blocked by dependencies
- **step-ca**: 0% - Cannot build until dependencies resolved

## Understanding Agiligo's Changes

### Key Finding: Functions Were Relocated, Not Removed

Agiligo reorganized crypto functions into algorithm-specific packages to support a **registry-based crypto-agile architecture**:

| Old Location (Standard Go) | New Location (Agiligo) |
|----------------------------|------------------------|
| `x509.ParsePKCS1PrivateKey` | `rsa.ParsePKCS1PrivateKey` |
| `x509.ParsePKCS8PrivateKey` | `pkcs8.UnmarshalPKCS8PrivateKey` |
| `x509.ParseECPrivateKey` | `ecdsa.ParseECPrivateKey` |
| `x509.ParsePKIXPublicKey` | `pkixparser.GetPublicKeyFromPKIXPublicKeyInfo` (two-step) |
| `x509.MarshalPKCS1PrivateKey` | `rsa.MarshalPKCS1PrivateKey` |
| `x509.MarshalECPrivateKey` | `ecdsa.MarshalECPrivateKey` |

### Registry-Based Architecture

Agiligo replaces hard-coded algorithm lists with dynamic registration:

```go
// Algorithms register themselves in init() functions
var crypto.PublicKeyAlgorithms map[string]PublicKeyAlgorithm
var crypto.SignatureAlgorithms map[string]SignatureAlgorithm
```

**Critical requirement:** Applications must import `crypto/init` or specific algorithm packages to register algorithms.

### Interface Changes (BREAKING)

```go
// New requirements in Agiligo
type PublicKey interface {
    Equal(x PublicKey) bool  // NEW
}

type PrivateKey interface {
    Public() PublicKey
    Equal(x PrivateKey) bool  // NEW
}
```

### Type Constants Removed

- `x509.RSA`, `x509.ECDSA`, `x509.Ed25519` no longer exist
- Use type switches or `algorithm.GetPublicKeyAlgorithmName()` instead

## Our Compatibility Solution

### x509compat Package

Created `/workspace/crypto-agiligo/x509compat/` that provides the old x509 API as wrapper functions:

```go
// Example: ParsePKCS8PrivateKey delegates to new location
func ParsePKCS8PrivateKey(der []byte) (crypto.PrivateKey, error) {
    return pkcs8.UnmarshalPKCS8PrivateKey(der)
}
```

**Coverage:**
- ✅ All Parse* functions (PKCS1, PKCS8, EC, PKIX)
- ✅ All Marshal* functions (PKCS1, PKCS8, EC, PKIX)
- ✅ Type constants (RSA, ECDSA, Ed25519)
- ✅ Helper functions (GetPublicKeyAlgorithm, IsRSA, IsECDSA, IsEd25519)

**Usage in crypto-agiligo:**
```go
import (
    _ "crypto/init"  // Register all Agiligo algorithms
    "go.step.sm/crypto/x509compat"
)

// Use old API names
key, err := x509compat.ParsePKCS8PrivateKey(derBytes)
```

### Files Updated

- `crypto-agiligo/pemutil/pem.go` - 11 function calls updated
- `crypto-agiligo/pemutil/cosign.go` - 1 function call updated

## The Blocker: Third-Party Dependencies

Our compatibility layer works perfectly for code we control, but **cannot fix cached third-party dependencies**.

### Critical Blocking Dependencies

**High Priority (Core Functionality):**
- `golang.org/x/crypto/ssh` - SSH protocol operations
- `golang.org/x/crypto/pkcs12` - PKCS#12 format
- `github.com/golang-jwt/jwt/v5` - JWT tokens
- `github.com/Masterminds/sprig/v3` - Template functions
- `github.com/google/s2a-go` - Google security (uses x509.RSA constants)

**Medium Priority (Cloud/Hardware):**
- `cloud.google.com/go/auth` - Google Cloud authentication
- `golang.org/x/oauth2` - OAuth2 authentication
- `github.com/smallstep/scep` - SCEP protocol
- `github.com/smallstep/pkcs7` - PKCS#7 support
- `github.com/ThalesIgnite/crypto11` - PKCS#11/HSM
- `github.com/go-piv/piv-go/v2` - YubiKey PIV

### Why This Blocks Progress

These dependencies are:
1. Downloaded from go.mod as pre-compiled modules
2. Stored in `/go/pkg/mod/` (read-only cache)
3. Cannot be patched without forking

**Impact:**
- ❌ pemutil (depends on golang.org/x/crypto/ssh)
- ❌ jose (depends on github.com/golang-jwt/jwt)
- ❌ keyutil (depends on pemutil → ssh)
- ❌ x509util (depends on keyutil)
- ❌ All KMS providers (depend on cloud auth libraries)
- ❌ step-ca build (cascading dependency failures)

### Agiligo's x/crypto Support

**Key Discovery:** Agiligo does **NOT** ship with a compatible golang.org/x/crypto alternative.

- Agiligo includes minimal vendored x/crypto (only 6 packages for Go toolchain internals)
- Does **NOT** include: ssh, pkcs12, ocsp, bcrypt, argon2, poly1305, etc.
- No application-level x/crypto support provided

**Implication:** Must fork golang.org/x/crypto and many other dependencies to proceed with Agiligo.

## Path Forward: Three Options

### Option A: Fork Critical Dependencies (Agiligo Approach)

**Strategy:**
1. Fork `golang.org/x/crypto` - Apply x509compat-style patches to ssh, pkcs12, ocsp packages
2. Fork `github.com/smallstep/scep` and `github.com/smallstep/pkcs7` (we control these)
3. Update go.mod replace directives
4. Maintain forks and sync with upstream updates

**Pros:**
- Complete control over the code
- Eventual upstream contribution possible

**Cons:**
- **8-12 weeks estimated effort**
- Maintenance burden (10+ forked repositories)
- Complex dependency management
- Need to sync with upstream continuously

### Option B: Alternative PQC Library (RECOMMENDED)

**Use Cloudflare CIRCL instead of Agiligo:**

Cloudflare CIRCL (https://github.com/cloudflare/circl) provides production-ready PQC algorithms:
- Pure Go implementation
- ML-DSA (Dilithium) and ML-KEM (Kyber) support
- **No forking required** - works with standard Go
- FIPS 203/204 compliant
- Battle-tested in Cloudflare production

**Approach:**
1. Implement `crypto.Signer` interface for CIRCL ML-DSA keys
2. Update step-ca certificate templates to support PQC signature algorithms
3. Add PQC key generation to CLI
4. No compatibility shims needed

**Pros:**
- **5-7 days estimated effort** (vs 8-12 weeks for Agiligo)
- Zero dependency forking
- Works with standard Go toolchain
- Production-ready and well-maintained
- Lower long-term maintenance

**Cons:**
- Don't get Agiligo's full crypto-agility framework
- Need to integrate PQC algorithms ourselves
- But we only need PQC algorithms, not full crypto-agility

### Option C: Wait for Ecosystem

Wait for:
1. Agiligo to gain broader adoption
2. golang.org/x/crypto to add Agiligo support
3. Other dependencies to update

**Pros:** No maintenance burden

**Cons:** Could take months/years, blocks all progress

## Development Roadmap

### If Choosing Agiligo (Option A)

**Phase 2: Fork Dependencies (8-12 weeks)**
1. Fork golang.org/x/crypto with patches
2. Fork Smallstep packages (scep, pkcs7)
3. Disable non-essential features temporarily
4. Get crypto-agiligo building (80%+ package success)
5. Get step-ca building

**Phase 3: PQC Certificate Issuance (4-6 weeks)**
1. ML-DSA key generation
2. PQC certificate templates
3. Update provisioners for algorithm selection
4. ACME protocol support for PQC

**Phase 4: Hybrid Certificates (4-6 weeks)**
1. Dual certificate issuance (classical + PQC)
2. Certificate linking via extensions
3. Client validation support

**Total: 16-24 weeks**

### If Choosing CIRCL (Option B)

**Phase 1: Proof of Concept (5-7 days)**
1. Implement crypto.Signer for CIRCL ML-DSA
2. Create minimal test: issue one ML-DSA certificate
3. Validate with standard crypto/x509

**Phase 2: Integration (2-3 weeks)**
1. Add PQC key generation to step CLI
2. Update certificate templates
3. Add provisioner algorithm selection
4. ACME support

**Phase 3: Production Ready (2-3 weeks)**
1. Testing and validation
2. Documentation
3. Performance optimization
4. Hybrid certificate support

**Total: 5-7 weeks**

## Comparison: Agiligo vs CIRCL

| Aspect | Agiligo | Cloudflare CIRCL |
|--------|---------|------------------|
| **Time to MVP** | 8-12 weeks | 5-7 days |
| **Dependency Forks** | 10+ repositories | Zero |
| **Maintenance** | High (ongoing sync) | Low (standard Go) |
| **Crypto-Agility** | Full framework | Manual integration |
| **Production Ready** | Experimental | Battle-tested |
| **Standards Support** | FIPS 203/204 | FIPS 203/204 |
| **Ecosystem** | Emerging | Mature |

## Next Steps & Recommendations

### Immediate Decision Required

**Choose PQC approach:**
1. **Option A (Agiligo)** - If full crypto-agility framework is critical
2. **Option B (CIRCL)** - If PQC support is the primary goal ⭐ RECOMMENDED

### If Proceeding with Agiligo

**Priority 1:** Fork golang.org/x/crypto
1. Clone https://github.com/golang/crypto
2. Apply x509compat-style patches
3. Test with crypto-agiligo
4. Update go.mod replace directive

**Priority 2:** Fork Smallstep packages
- github.com/smallstep/scep
- github.com/smallstep/pkcs7

**Priority 3:** Disable non-essential features
- Use build tags for MySQL, Vault, some cloud KMS

### If Switching to CIRCL

**Priority 1:** Proof of Concept
1. Install CIRCL: `go get github.com/cloudflare/circl`
2. Implement crypto.Signer for ML-DSA keys
3. Issue test certificate with x509.CreateCertificate
4. Validate approach

**Priority 2:** Design Integration
- Update step-ca authority package
- Design CLI interface for PQC
- Plan certificate template changes

## Troubleshooting

### Build failures with crypto dependencies
- Ensure submodules are initialized: `git submodule update --init --recursive`
- Check that `go.step.sm/crypto` replace directive points to `./crypto-agiligo` in `go.mod`
- Use `GOWORK=off` flag if encountering workspace issues

### Container issues
```bash
# Rebuild container from scratch
docker compose build --no-cache

# Remove old containers/images
docker compose down
docker system prune -a
```

### Claude Code not working
- Ensure you're authenticated on host: `claude auth login` (run on host, not in container)
- Check credentials exist: `ls ~/.claude`
- The container automatically mounts `~/.claude` to `/root/.claude`

### Permission errors with /go/pkg
```bash
# Fix Go module cache permissions
sudo chown -R $(id -u):$(id -g) /go/pkg
```

## Resources

### Agiligo
- [Agiligo GitHub Repository](https://github.com/ISRI-PQC/agiligo)
- Agiligo source: `/usr/local/agiligo/src/`
- Agiligo docs: `/usr/local/agiligo/README*.md`

### Cloudflare CIRCL
- [CIRCL GitHub Repository](https://github.com/cloudflare/circl)
- [CIRCL Documentation](https://pkg.go.dev/github.com/cloudflare/circl)

### Standards
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

### step-ca
- [step-ca Documentation](https://smallstep.com/docs/step-ca)
- [step CLI Documentation](https://smallstep.com/docs/step-cli)

## Contributing

When contributing to this Agiligo exploration:

1. Use Docker Compose for all development (`docker compose run --rm dev`)
2. Ensure all builds and tests pass with Agiligo toolchain
3. Document any new PQC-specific features
4. Update this guide if you discover new setup steps or issues
5. Consider the CIRCL alternative for production PQC needs

## Project Files

- `AGILIGO-TODO.md` - Detailed task tracking and progress
- `crypto-agiligo/` - Git submodule for go.step.sm/crypto fork
- `crypto-agiligo/x509compat/` - Compatibility layer for Agiligo API changes
- `Dockerfile` - Container build configuration
- `docker-compose.yml` - Development environment setup
