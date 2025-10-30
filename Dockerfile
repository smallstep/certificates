FROM mcr.microsoft.com/devcontainers/go:1.24 AS base

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libc6-dev \
        netbase \
        ca-certificates \
        curl \
        wget \
        git \
        bash \
        gcc \
        libpcsclite-dev \
        make \
        dnsutils \
        && update-ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# ============================================================================
# AGILIGO BUILD LAYER - This layer is cached separately
# ============================================================================
FROM base AS agiligo-builder

WORKDIR /usr/local/agiligo
ENV GOROOT_BOOTSTRAP=/usr/local/go

# Clone and build Agiligo (this is the expensive operation we want to cache)
RUN git clone --depth 1 https://github.com/ISRI-PQC/agiligo.git . && \
    cd src && \
    ./all.bash

# ============================================================================
# FINAL DEVELOPMENT IMAGE
# ============================================================================
FROM base AS dev

# Copy Agiligo from builder stage
COPY --from=agiligo-builder /usr/local/agiligo /usr/local/agiligo

# Configure Agiligo environment
ENV GOROOT=/usr/local/agiligo
ENV PATH=/usr/local/agiligo/bin:$PATH

# Install Node.js and npm for Claude Code CLI
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs npm && \
    rm -rf /var/lib/apt/lists/*

# Install Go development tools (these change less frequently than Agiligo)
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install gotest.tools/gotestsum@latest

# Install Claude Code CLI via npm
RUN npm install -g @anthropic-ai/claude-code

# Create workspace directory and set ownership for vscode user
RUN mkdir -p /workspace && chown -R vscode:vscode /workspace

# Initialize submodules on container start
RUN echo 'if [ -d /workspace/.git ]; then cd /workspace && git submodule update --init --recursive 2>/dev/null || true; fi' >> /home/vscode/.bashrc

# Switch to non-root user
USER vscode

# Set working directory for step-ca development
WORKDIR /workspace
