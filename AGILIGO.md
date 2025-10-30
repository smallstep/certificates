# Agiligo Development Guide

This fork of step-ca uses the [Agiligo Go variant](https://github.com/ISRI-PQC/agiligo) to enable post-quantum cryptographic support. Agiligo is a modified version of the Go toolchain that adds cryptographic agility features, allowing the use of post-quantum algorithms not yet available in mainline Go.

## Quick Start

**This project requires Docker Compose** - the Agiligo Go toolchain is built and configured automatically inside a container. All development must be done in the container environment.

### Prerequisites

- Docker with Compose V2 support (`docker compose` command)
- Claude Code CLI installed and authenticated on your host machine
  - Install: `npm install -g @anthropic-ai/claude-code`
  - Authenticate: `claude auth login`
  - Your credentials (`~/.claude`) will be automatically mounted in the container

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

**Note:** The first build takes ~10-15 minutes to compile Agiligo from source. Subsequent starts are much faster thanks to Docker layer caching.

## Container Features

The development container includes:
- **Agiligo Go Toolchain** - Built from source (GOROOT: `/usr/local/agiligo`)
- **Development Tools**: make, golangci-lint, govulncheck, gotestsum
- **Claude Code CLI** - Pre-installed and ready to use
- **DNS Configuration**: Google DNS (8.8.8.8, 8.8.4.4) for reliable connectivity
- **Claude Credentials**: Mounted from `~/.claude` on host
- **Dependencies**: libpcsclite-dev for HSM support

## Building step-ca with Agiligo

### Dependencies

This fork uses a git submodule for the `go.step.sm/crypto` library at `./crypto-agiligo` on the `agiligo-pqc` branch. The submodule is automatically configured in `go.mod`:

```go
replace go.step.sm/crypto => ./crypto-agiligo
```

The crypto submodule is automatically initialized when you start the container.

### Build Commands

All commands should be run inside the container:

```bash
# Download dependencies
make download

# Build step-ca
make build

# Run all tests (includes TPM simulator tests)
make test

# Run only default tests
make testdefault

# Run integration tests
make integration

# Lint code
make lint
```

## Development Workflow

```bash
# 1. Start container
docker compose run --rm dev

# 2. Inside container - make changes and test
make build
make test

# 3. Use Claude Code for assistance
claude

# 4. Exit when done
exit
```

## Known Limitations

### Current Status
- ✅ Build system configured for Agiligo
- ✅ Docker Compose development environment
- ✅ `go.step.sm/crypto` submodule added (`crypto-agiligo/` on `agiligo-pqc` branch)
- ✅ Claude Code CLI available in container
- ⚠️ Post-quantum algorithms not yet implemented (hybrid mode planned)
- ❌ CI/CD not yet configured for Agiligo
- ❌ Production Docker images not yet available

### Dependencies
- `go.step.sm/crypto` - **Available as git submodule** at `./crypto-agiligo` (branch: `agiligo-pqc`)
- Other crypto-heavy dependencies may require updates as PQC work progresses

## Troubleshooting

### Build failures with crypto dependencies
- Ensure submodules are initialized: `git submodule update --init --recursive`
- Check that `go.step.sm/crypto` replace directive points to `./crypto-agiligo` in `go.mod`

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

## Architecture Notes

### Cryptographic Agility Strategy
This fork is preparing for hybrid mode, where both classical and post-quantum cryptography coexist:

- **Phase 1 (Current):** Build infrastructure - get step-ca building with Agiligo
- **Phase 2 (Planned):** Implement PQC algorithms alongside classical crypto
- **Phase 3 (Future):** Full hybrid certificate support

### Modified Dependencies
- `go.step.sm/crypto` - Core crypto wrapper library (requires Agiligo rebuild)
- Standard library `crypto/*` - Using Agiligo's modified versions
- `golang.org/x/crypto` - May need updates for PQC algorithm support

## Resources

- [Agiligo GitHub Repository](https://github.com/ISRI-PQC/agiligo)
- [step-ca Documentation](https://smallstep.com/docs/step-ca)
- [Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Contributing

When contributing to this Agiligo fork:

1. Use Docker Compose for all development (`docker compose run --rm dev`)
2. Ensure all builds and tests pass with Agiligo toolchain
3. Document any new PQC-specific features
4. Update this guide if you discover new setup steps or issues
