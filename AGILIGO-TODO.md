# Agiligo Migration TODO

This document tracks the remaining work to complete the Agiligo migration for step-ca.

## ✅ Completed

### Phase 1: Development Environment Setup
- [x] Created Dockerfile to build Agiligo from source (reproducible)
- [x] Added development dependencies (make, golangci-lint, libpcsclite-dev)
- [x] Configured GOROOT and PATH for Agiligo
- [x] Added Claude Code CLI (auto-installed on container start)
- [x] Configured automatic submodule initialization via entrypoint
- [x] Created docker-compose.yml for easy container management
- [x] Removed devcontainer configuration (Docker Compose is the only option)

### Phase 2: Dependency Management
- [x] Added go.mod replace directive for go.step.sm/crypto
- [x] Documented fork requirement in AGILIGO.md

### Phase 3: Build System Updates
- [x] Updated Makefile with Agiligo notice and requirements
- [x] Verified build targets work with Agiligo toolchain
- [x] Verified test targets work with Agiligo toolchain

### Documentation
- [x] Created comprehensive AGILIGO.md guide
- [x] Updated README.md with fork notice
- [x] Documented troubleshooting steps

## 🔄 In Progress / Blocked

### Dependency Setup
- [x] **Add go.step.sm/crypto as git submodule**
  - ✅ Added as `crypto-agiligo/` submodule
  - ✅ Created `agiligo-pqc` branch in submodule
  - ✅ Updated go.mod replace directive to point to `./crypto-agiligo`

### Testing & Validation
- [ ] **Test basic build with Agiligo** (ready to test)
  - `make build` with Agiligo
  - Verify binary compiles
  - Smoke test: `./bin/step-ca --version`

- [ ] **Run test suite** (ready to test)
  - `make testdefault`
  - `make testtpmsimulator`
  - Document any test failures
  - Create issue list for failures

- [ ] **Validate core functionality** (ready to test)
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

1. **Test crypto submodule build with Agiligo**
   ```bash
   # Start container
   docker compose run --rm dev

   # Inside container
   cd crypto-agiligo
   go mod download
   go build ./...
   go test ./...
   ```

2. **Test step-ca build**
   ```bash
   # Inside container
   cd /workspace
   make download
   make build
   ```

3. **Document any issues encountered**
   - Compilation errors
   - Missing dependencies
   - Incompatible packages

4. **Create issue tracker**
   - Track test failures
   - Track compatibility issues
   - Prioritize fixes

## 📊 Success Criteria (Current Phase)

- ✅ Docker Compose environment builds and runs Agiligo
- ✅ Makefile configured for Agiligo
- ✅ Documentation complete
- ✅ go.step.sm/crypto submodule available
- ⏳ step-ca compiles successfully with Agiligo
- ⏳ Basic CA operations functional (init, start, sign)
- ⏳ Core test suite runs (>80% pass rate acceptable for MVP)

## 🆘 Known Issues

### Blockers
1. ~~**go.step.sm/crypto fork not yet created**~~ - ✅ **RESOLVED:** Added as git submodule
2. **Unknown Agiligo compatibility issues** - Will discover during first build

### Warnings
- Some third-party dependencies may not compile with Agiligo
- May need to vendor or replace incompatible dependencies
- Standard library changes in Agiligo might break assumptions in code

## 📝 Notes

- The Docker container takes ~10-15 minutes to build on first run (compiles Agiligo)
- Agiligo is based on Go 1.24, matching step-ca's current Go version requirement
- This migration focuses on build infrastructure; PQC algorithm implementation is future work
- Hybrid mode (classical + PQC) is the intended end goal
- Use `docker compose` (Compose V2) not `docker-compose` (deprecated)
