# syntax=docker/dockerfile:1.4
# Build stage
FROM golang:1.24.2-alpine3.21 AS builder

# Build arguments
ARG VERSION=development
ARG COMMIT=unknown
ARG BUILD_DATE
ARG USER=appuser
ARG UID=10001

# Environment variables
ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

# Install required packages
# Package names sorted alphanumerically
RUN apk add --no-cache --virtual .build-deps \
    ca-certificates \
    git \
    make \
    && addgroup -g ${UID} ${USER} \
    && adduser -D -u ${UID} -G ${USER} ${USER} \
    && mkdir -p /go/pkg/mod /go/src \
    && chown -R ${USER}:${USER} /go /app

# Switch to non-root user for build
USER ${USER}

# Copy go.mod and go.sum first to leverage Docker cache
COPY --chown=${USER}:${USER} go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY --chown=${USER}:${USER} . .

# Build the binary with security flags
RUN go build -a -trimpath -installsuffix cgo -ldflags="-extldflags \"-static\" -s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" -o bin/server ./cmd/server

# Generate SBOM for the build stage
FROM alpine:3.21 AS sbom-generator
RUN apk add --no-cache syft
COPY --from=builder /app /app
RUN syft /app -o spdx-json=/sbom.json

# Final stage
FROM alpine:3.21

# Build arguments for final stage
ARG VERSION
ARG BUILD_DATE
ARG USER=appuser
ARG UID=10001

# Runtime environment variables
ENV APP_USER=${USER} \
    APP_UID=${UID} \
    GIN_MODE=release \
    CONFIG_FILE=/app/configs/config.yaml \
    TZ=UTC

# Install runtime dependencies and setup user with a single RUN command to reduce layers
# Package names sorted alphanumerically for better maintainability
RUN apk add --no-cache \
    ca-certificates \
    curl \
    tzdata \
    && addgroup -g ${UID} ${USER} \
    && adduser -D -u ${UID} -G ${USER} ${USER} \
    # Create directories with appropriate permissions
    && mkdir -p /app/data /app/configs /app/logs \
    # Set proper ownership without excessive permissions
    && chown -R ${USER}:${USER} /app \
    # Set appropriate permissions: 755 for directories (rwxr-xr-x)
    && find /app -type d -exec chmod 755 {} \; \
    # Create a default empty config
    && echo "# Default config created during Docker build" > /app/configs/config.yaml \
    # Set appropriate permissions: 644 for files (rw-r--r--)
    && chmod 644 /app/configs/config.yaml

WORKDIR /app

# Copy the binary and SBOM from previous stages
COPY --from=builder --chown=${USER}:${USER} /app/bin/server /app/
COPY --from=sbom-generator /sbom.json /app/sbom.json

# Ensure the binary is executable without excessive permissions
RUN chmod 755 /app/server

# Switch to non-root user
USER ${USER}

# Note: Security capabilities like --cap-drop=ALL should be applied at runtime
# Example: docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE [image]

# Add metadata
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="wyattroersma@gmail.com" \
      org.opencontainers.image.url="https://github.com/ThreatFlux/dockerServerMangerGoMCP" \
      org.opencontainers.image.documentation="https://github.com/ThreatFlux/dockerServerMangerGoMCP" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/dockerServerMangerGoMCP" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.title="server" \
      org.opencontainers.image.description="ThreatFlux Server Application" \
      org.opencontainers.image.licenses="MIT" \
      com.threatflux.image.created.by="Docker" \
      com.threatflux.image.created.timestamp="${BUILD_DATE}" \
      com.threatflux.sbom.path="/app/sbom.json"

# Expose API port
EXPOSE 8080

# Improved health check with reasonable intervals and better process checking
# Using curl to check health endpoint as in the original example
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

# Set the entrypoint with exec form
CMD ["/app/server"]