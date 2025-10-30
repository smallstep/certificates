# Agiligo Migration TODO

This document tracks the remaining work to complete the Agiligo migration for step-ca.

## 🔄 In Progress / Blocked

### Dependency Setup
- [x] **Add go.step.sm/crypto as git submodule**
  - ✅ Added as `crypto-agiligo/` submodule
  - ✅ Created `agiligo-pqc` branch in submodule
  - ✅ Updated go.mod replace directive to point to `./crypto-agiligo`

### Testing & Validation
- [x] **Test crypto submodule build** ⚠️ PARTIAL SUCCESS
  - ✅ Dependencies download successfully
  - ⚠️ Build has compilation errors in third-party dependencies
  - ⚠️ Tests: 14/42 packages pass (33.3% pass rate)
  - See "Build Issues" section below for details

- [x] **Test step-ca build with Agiligo** ❌ **FAILED**
  - ❌ Build fails with same x509 API errors as crypto submodule
  - ❌ Blocked by third-party dependency incompatibilities
  - ❌ Cannot produce binary until crypto issues resolved

- [ ] **Run step-ca test suite** (ready to test)
  - `make testdefault`
  - `make testtpmsimulator`
  - Document any test failures
  - Create issue list for failures

- [ ] **Validate core functionality** (blocked until builds work)
  - Initialize CA: `step-ca init`
  - Issue certificate
  - Test ACME protocol
  - Test provisioner authentication

## 🔮 Future Work (Out of Current Scope)

### Phase 4: Post-Quantum Algorithms
- [ ] Research and document PQC algorithms to support (ML-KEM, ML-DSA, etc.)
- [ ] Design hybrid certificate format (classical + PQC)
- [ ] Implement PQC key generation
- [ ] Implement PQC certificate signing
- [ ] Add PQC cipher suites to TLS configuration
- [ ] Update provisioners to support PQC authentication

### Phase 5: KMS & Hardware Integration
- [ ] Test cloud KMS compatibility (AWS, Azure, GCP)
- [ ] Verify HSM/PKCS#11 support with PQC
- [ ] Test TPM integration with Agiligo
- [ ] YubiKey compatibility testing

### Phase 6: CI/CD & Release
- [ ] Update GitHub Actions to use Agiligo
- [ ] Create Agiligo-based Docker images
- [ ] Update GoReleaser configuration
- [ ] Multi-platform builds with Agiligo
- [ ] Automated testing in CI

### Phase 7: Advanced Features
- [ ] Certificate chain validation with mixed algorithms
- [ ] Backward compatibility mode (classical-only fallback)
- [ ] Performance optimization for PQC operations
- [ ] Comprehensive integration tests
- [ ] Load testing with PQC certificates

## 📋 Immediate Next Steps

### Phase 2A: COMPLETE ✅
1. ✅ Created x509compat package with full API coverage
2. ✅ Added crypto/init imports
3. ✅ Updated pemutil to use compatibility layer
4. ✅ Comprehensive test suite (all tests passing)

### Phase 2B: DECISION POINT ⚠️

**Current Status:** Compatibility layer works, but blocked by third-party dependencies.

**Options:**

**A. Fork Critical Dependencies** (RECOMMENDED)
```bash
# 1. Fork golang.org/x/crypto
git clone https://github.com/golang/crypto
cd crypto
# Apply x509compat-style patches to ssh, pkcs12, ocsp
# Create branch: agiligo-compat

# 2. Update go.mod in crypto-agiligo and step-ca
replace golang.org/x/crypto => github.com/smallstep/crypto-agiligo-deps v0.43.0
```

**B. Disable Non-Essential Features**
```bash
# Use build tags to exclude:
# - MySQL support
# - Some KMS providers
# - Vault integration
# Get minimal step-ca building first
```

**C. Hybrid Approach** (PRACTICAL)
- Fork golang.org/x/crypto (most critical)
- Fork smallstep/* packages (we control these)
- Disable less-critical cloud features temporarily
- Document all changes for upstream contributions

### Success Metrics (Updated)
- ✅ x509compat package builds without errors
- ✅ x509compat tests pass (100%)
- ⚠️ crypto-agiligo blocked by external deps
- ⚠️ step-ca blocked by cascading failures

**Next Decision:** Choose dependency strategy before proceeding

## 📊 Success Criteria (Current Phase)

### Phase 1: Build Infrastructure ✅ COMPLETE
- ✅ Docker Compose environment builds and runs Agiligo
- ✅ Makefile configured for Agiligo
- ✅ Documentation complete
- ✅ go.step.sm/crypto submodule available
- ✅ Initial build testing completed
- ✅ Agiligo API investigation complete
- ✅ Compatibility strategy defined

### Phase 2: Compatibility Layer ⚠️ PARTIAL - BLOCKED
- ✅ x509compat package created and tested
- ✅ crypto-agiligo code updated to use compatibility layer
- ❌ crypto-agiligo builds - **BLOCKED by third-party dependencies**
- ⏳ crypto-agiligo tests pass (>80% target) - Cannot test until builds

**Blocker:** Third-party dependencies (golang.org/x/crypto, jwt, cloud auth, etc.) use old x509 API

**See:** `AGILIGO.md` (sections "The Blocker: Third-Party Dependencies" and "Path Forward") for detailed analysis

### Phase 3: step-ca Integration (BLOCKED)
- ⏳ step-ca compiles successfully with Agiligo
- ⏳ Basic CA operations functional (init, start, sign)
- ⏳ Core test suite runs (>80% pass rate acceptable for MVP)

## 🐛 Build Issues Found

### crypto-agiligo Test Results (as of 2025-10-30)

**Summary:**
- ✅ 14 packages pass all tests
- ❌ 28 packages fail to build (build errors)
- 📊 Pass rate: 33.3% (below 80% target)

**Passing Packages:**
- go.step.sm/crypto/fingerprint
- go.step.sm/crypto/fipsutil
- go.step.sm/crypto/internal/bcrypt_pbkdf
- go.step.sm/crypto/internal/emoji
- go.step.sm/crypto/internal/utils/asn1
- go.step.sm/crypto/internal/utils/convert
- go.step.sm/crypto/internal/utils/file
- go.step.sm/crypto/internal/utils/utfbom
- go.step.sm/crypto/kms/apiv1
- go.step.sm/crypto/kms/uri
- go.step.sm/crypto/randutil
- go.step.sm/crypto/tpm/algorithm
- go.step.sm/crypto/tpm/manufacturer
- go.step.sm/crypto/tpm/tss2

**Critical Issues:**

1. **crypto/x509 API Changes** - Many third-party dependencies fail
   - Missing functions: `ParsePKCS1PrivateKey`, `ParsePKCS8PrivateKey`, `ParseECPrivateKey`, `ParsePKIXPublicKey`
   - Missing functions: `MarshalPKCS1PrivateKey`, `MarshalECPrivateKey`, `MarshalPKCS8PrivateKey`
   - Missing constants: `x509.RSA`, `x509.ECDSA`, `x509.Ed25519`

   **Affected packages:**
   - golang.org/x/crypto/ssh
   - golang.org/x/oauth2/internal
   - cloud.google.com/go/auth/internal
   - github.com/go-jose/go-jose/v3 (via dependencies)
   - github.com/Masterminds/sprig/v3
   - github.com/golang-jwt/jwt/v5
   - golang.org/x/crypto/pkcs12
   - github.com/googleapis/enterprise-certificate-proxy
   - github.com/google/s2a-go

2. **crypto.PrivateKey Interface Changes**
   - New `Equal` method required on crypto.PrivateKey/PublicKey
   - Type switches on concrete types fail (rsa.PrivateKey, ecdsa.PrivateKey)

   **Affected packages:**
   - github.com/ThalesIgnite/crypto11
   - github.com/go-piv/piv-go/v2
   - github.com/google/certificate-transparency-go/tls
   - go.step.sm/crypto/x25519 (internal tests)

3. **Build-Blocking Packages:**
   - ❌ go.step.sm/crypto/jose (JWT/JWS/JWE - CRITICAL)
   - ❌ go.step.sm/crypto/keyutil (key parsing - CRITICAL)
   - ❌ go.step.sm/crypto/pemutil (PEM handling - CRITICAL)
   - ❌ go.step.sm/crypto/sshutil (SSH operations)
   - ❌ go.step.sm/crypto/tlsutil (TLS utilities)
   - ❌ go.step.sm/crypto/x509util (x509 utilities - CRITICAL)
   - ❌ All KMS providers (awskms, azurekms, cloudkms, pkcs11, tpmkms, yubikey)

### Root Cause Analysis

Agiligo has modified the standard library crypto packages to support post-quantum algorithms. These changes include:
1. **Restructured x509 parsing/marshaling functions** - Likely consolidated or renamed
2. **Modified crypto.PrivateKey interface** - Added Equal() method for key comparison
3. **Changed key type constants** - x509.RSA, x509.ECDSA, x509.Ed25519 removed or relocated

### Impact Assessment

🔴 **HIGH IMPACT** - Critical crypto functionality blocked:
- Certificate parsing and generation (x509util, pemutil)
- JWT/JWS operations (jose)
- Key management (keyutil)
- All cloud KMS providers

🟡 **MEDIUM IMPACT** - Hardware/specialized features:
- TPM operations
- YubiKey support
- PKCS#11/HSM integration

🟢 **LOW IMPACT** - Internal utilities mostly work:
- Fingerprinting, hashing, random utilities
- Internal data structures

### Next Steps to Unblock

**Option A: Fix in crypto-agiligo fork** (RECOMMENDED)
1. Add compatibility shims for x509 functions
2. Update go.step.sm/crypto code to use new Agiligo APIs
3. Fix Equal() method implementations
4. Update type assertions for new crypto interfaces

**Option B: Wait for upstream Agiligo fixes**
- Track Agiligo project for stdlib compatibility updates
- May require engagement with Agiligo team

**Option C: Vendor and patch dependencies**
- Fork problematic dependencies
- Patch to work with Agiligo
- Maintain as separate vendored copies

**Immediate Action:** Proceed to test step-ca build to assess if any direct code works without crypto dependencies.

### step-ca Build Results (as of 2025-10-30)

**Status:** ❌ **FAILED** - Cannot build step-ca binary

**Root Cause:** Same x509 API incompatibilities blocking crypto submodule

**Build Errors:**
1. `github.com/Masterminds/sprig/v3` - x509.MarshalPKCS1PrivateKey, ParsePKCS8PrivateKey, etc.
2. `golang.org/x/crypto/ssh` - x509 parsing functions
3. `github.com/google/s2a-go` - x509.RSA, x509.ECDSA, x509.Ed25519 constants
4. Cascading failures through all dependencies

**Conclusion:** Cannot proceed with step-ca testing until crypto compatibility layer is implemented in crypto-agiligo fork.

**Required Fix Path:**
1. ✅ **COMPLETE** - Investigate Agiligo's x509 package to understand the new API
2. Create compatibility shims in crypto-agiligo
3. Update crypto-agiligo code to use new Agiligo APIs
4. Rebuild and test until step-ca compiles

### Agiligo API Investigation Results (2025-10-30)

**Status:** ✅ **INVESTIGATION COMPLETE** - Full API mapping documented

See detailed report in `AGILIGO.md` (section "Understanding Agiligo's Changes")

**Key Findings:**

1. **Functions Not Removed - Just Relocated!**
   - `x509.ParsePKCS1PrivateKey` → `rsa.ParsePKCS1PrivateKey`
   - `x509.ParsePKCS8PrivateKey` → `pkcs8.UnmarshalPKCS8PrivateKey`
   - `x509.ParseECPrivateKey` → `ecdsa.ParseECPrivateKey`
   - `x509.ParsePKIXPublicKey` → Two-step: `pkix.UnmarshalPKIXPublicKeyInfo` + `pkixparser.GetPublicKeyFromPKIXPublicKeyInfo`
   - All Marshal* functions similarly relocated

2. **Architecture Change: Registry-Based System**
   ```go
   // Algorithms now register themselves
   crypto.PublicKeyAlgorithms map[string]PublicKeyAlgorithm
   crypto.SignatureAlgorithms map[string]SignatureAlgorithm
   ```

3. **Required Initialization**
   - Must import `crypto/init` or individual algorithm packages
   - Algorithms register in their init() functions

4. **Interface Changes (BREAKING)**
   ```go
   // New requirements
   type PublicKey interface {
       Equal(x PublicKey) bool
   }
   type PrivateKey interface {
       Public() PublicKey
       Equal(x PrivateKey) bool
   }
   ```

5. **Type Constants Removed**
   - `x509.RSA`, `x509.ECDSA`, `x509.Ed25519` no longer exist
   - Use type switches or algorithm.GetPublicKeyAlgorithmName() instead

**Solution Strategy: Compatibility Shim Layer**

Create `crypto-agiligo/x509compat` package that:
- Wraps relocated functions with old names
- Provides type constants for backward compatibility
- Allows minimal changes to crypto-agiligo code
- Avoids forking dozens of dependencies

## 🆘 Known Issues

### Blockers
2. 🔴 **CRITICAL: step-ca cannot build** - Blocked by x509 API incompatibilities
3. 🔴 **CRITICAL: 28/42 crypto packages fail to build** - Third-party dependency issues
4. 🔴 **CRITICAL: Agiligo x509 API changes** - Missing Parse*/Marshal* functions, type constants

### Warnings
- ⚠️ Many third-party crypto dependencies don't compile with Agiligo
- ⚠️ Will need extensive compatibility shims or dependency updates
- ⚠️ KMS providers all blocked - cloud integration at risk

## 📝 Notes

- Agiligo is based on Go 1.24, matching step-ca's current Go version requirement
- This migration focuses on build infrastructure; PQC algorithm implementation is future work
- Hybrid mode (classical + PQC) is the intended end goal
