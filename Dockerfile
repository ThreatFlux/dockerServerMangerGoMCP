# Stage 1: Build the application
FROM golang:1.24-alpine AS builder

# Install necessary dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy Go modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static" -s -w' -o bin/server ./cmd/server

# Stage 2: Create minimal runtime image
FROM alpine:3.19

# Add CA certificates and other runtime deps
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create necessary directories with proper permissions
RUN mkdir -p /app/data /app/configs /app/logs \
    && chown -R appuser:appgroup /app

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder --chown=appuser:appgroup /app/bin/server /app/
COPY --from=builder --chown=appuser:appgroup /app/configs /app/configs/

# Set environment variables
ENV GIN_MODE=release \
    CONFIG_FILE=/app/configs/config.yaml \
    TZ=UTC

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/api/health || exit 1

# Run the application
CMD ["/app/server"]
