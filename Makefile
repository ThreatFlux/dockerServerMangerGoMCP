# Required versions
REQUIRED_GO_VERSION = 1.24.1
REQUIRED_DOCKER_VERSION = 24.0.0

# Tool paths and versions
GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOSEC ?= gosec
GOVULNCHECK ?= govulncheck
DOCKER ?= docker
COSIGN ?= cosign
SYFT ?= syft
DUPL ?= dupl

# Version information
VERSION ?= $(shell git describe --tags --always || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# Build flags
BUILD_FLAGS ?= -v
TEST_FLAGS ?= -v -race -cover
LINT_FLAGS ?= run --timeout=5m

# Coverage output paths
COVERAGE_PROFILE = coverage.out
COVERAGE_HTML = coverage.html

# Binary information
BINARY_NAME = docker-server-manager
BINARY_PATH = bin/$(BINARY_NAME)

# Docker information
DOCKER_REGISTRY ?= threatflux
DOCKER_IMAGE = $(DOCKER_REGISTRY)/$(BINARY_NAME)
DOCKER_TAG ?= $(VERSION)
DOCKER_LATEST = $(DOCKER_IMAGE):latest
DOCKER_DEV_IMAGE = $(DOCKER_REGISTRY)/go-dev

.PHONY: all build test lint clean docker-build check-versions install-tools security help version-info coverage dupl-check docker-push docker-sign docker-verify install docker-run fmt docker-test docker-tests docker-dev-build docker-fmt docker-lint docker-security docker-coverage docker-dupl-check docker-all docker-shell

# Version check targets
check-versions: ## Check all required tool versions
	@echo "Checking required tool versions..."
	@echo "Checking Go version..."
	@$(GO) version | grep -q "go$(REQUIRED_GO_VERSION)" || (echo "Error: Required Go version $(REQUIRED_GO_VERSION) not found" && exit 1)
	@echo "Checking Docker version..."
	@$(DOCKER) --version | grep -q "$(REQUIRED_DOCKER_VERSION)" || (echo "Warning: Recommended Docker version $(REQUIRED_DOCKER_VERSION) not found")
	@echo "All version checks completed"

# Install required tools
install-tools: ## Install required Go tools
	@echo "Installing security and linting tools..."
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/sonatype-nexus-community/nancy@latest
	@go install github.com/sigstore/cosign/cmd/cosign@latest
	@go install github.com/anchore/syft/cmd/syft@latest
	@go install github.com/mibk/dupl@latest

build: check-versions ## Build the application
	@echo "Building application..."
	@mkdir -p bin
	cd cmd/server/ && $(GO) build $(BUILD_FLAGS) \
		-ldflags="-X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(BUILD_DATE)" \
		-o ../../$(BINARY_PATH)

fmt: ## Format Go source files
	@echo "Formatting Go files..."
	@find . -name "*.go" -type f -not -path "./vendor/*" -exec $(GO) fmt {} \;

lint: install-tools ## Run golangci-lint for code analysis
	@echo "Running linters..."
	$(GOLANGCI_LINT) $(LINT_FLAGS) ./...

test: ## Run unit tests with coverage (5 min timeout)
	@echo "Running tests..."
	@$(GO) test $(TEST_FLAGS) -mod=vendor -timeout 5m ./...

coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	@$(GO) test -coverprofile=$(COVERAGE_PROFILE) ./...
	@$(GO) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	@$(GO) tool cover -func=$(COVERAGE_PROFILE)

dupl-check: install-tools ## Check for duplicate code
	@echo "Checking for duplicate code..."
	@$(DUPL) -t 75 -plumbing -verbose ./...
	@echo "Duplicate code check completed"

security: install-tools ## Run security scans
	@echo "Running security scans..."
	@$(GOSEC) ./...
	@$(GOVULNCHECK) ./...
	@go list -json -deps ./... | nancy sleuth

docker-build: check-versions ## Build Docker image
	@echo "Building Docker image..."
	@$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_LATEST) \
		.

docker-sign: ## Sign Docker image with cosign
	@echo "Signing Docker image..."
	@$(COSIGN) sign --key cosign.key $(DOCKER_IMAGE):$(DOCKER_TAG)
	@$(COSIGN) sign --key cosign.key $(DOCKER_LATEST)

docker-test: ## Test Docker image
	@echo "Testing Docker image..."
	@$(DOCKER) run \
		--cap-drop=ALL \
		$(DOCKER_IMAGE):$(DOCKER_TAG) -h

docker-verify: ## Verify Docker image signature
	@echo "Verifying Docker image signature..."
	@$(COSIGN) verify --key cosign.pub $(DOCKER_IMAGE):$(DOCKER_TAG)

docker-run: ## Run Docker container with security options
	@echo "Running Docker container with security options..."
	@$(DOCKER) run \
		--cap-drop=ALL \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

docker-push: docker-build docker-sign ## Push Docker image to registry
	@echo "Pushing Docker image..."
	@$(DOCKER) push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@$(DOCKER) push $(DOCKER_LATEST)

install: build ## Install the binary
	@echo "Installing $(BINARY_NAME)..."
	@install -m 755 $(BINARY_PATH) /usr/local/bin/$(BINARY_NAME)

clean: ## Remove build artifacts and generated files
	@echo "Cleaning all artifacts and generated files..."
	@rm -f $(BINARY_PATH)
	@rm -f $(COVERAGE_PROFILE)
	@rm -f $(COVERAGE_HTML)
	@rm -rf vendor/
	@rm -rf bin/
	@rm -f *.log
	@rm -f *.out
	@rm -f *.test
	@rm -f *.prof
	@rm -rf dist/
	@go clean -cache -testcache -modcache -fuzzcache

clean-cache: ## Clean Go build cache
	@echo "Cleaning Go build cache..."
	@$(GO) clean -cache

all: fmt test security lint dupl-check build docker-build ## Run all checks and build

help: ## Display available commands
	@echo "Available commands:"
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

version-info: ## Display version information
	@echo "Build Information:"
	@echo "  Version:    $(VERSION)"
	@echo "  Commit:     $(COMMIT)"
	@echo "  Build Date: $(BUILD_DATE)"
	@echo "\nRequired Versions:"
	@echo "  Go:     $(REQUIRED_GO_VERSION)+"
	@echo "  Docker: $(REQUIRED_DOCKER_VERSION)+"
	@echo "\nInstalled Versions:"
	@$(GO) version
	@$(DOCKER) --version


# API Documentation Generation
docs: ## Generate API documentation (Swagger 2.0 and OpenAPI 3.0)
	@echo "Generating API documentation..."
	@/Users/vtriple/go/bin/swag init -g cmd/server/main.go --parseDependency --output docs
	@echo "Converting Swagger 2.0 JSON to OpenAPI 3.0 JSON..."
	@swagger2openapi docs/swagger.json -o docs/openapi.json
	@echo "Converting Swagger 2.0 JSON to OpenAPI 3.0 YAML..."
	@swagger2openapi docs/swagger.json -o docs/openapi.yaml --yaml
	@echo "Documentation generation complete."

# Development server targets
PID_FILE = .server.pid

dev-start: clean-cache build ## Clean cache, build and start the server in the background, saving PID
	@echo "Starting development server in background..."
	@./$(BINARY_PATH) & echo $! > $(PID_FILE)
	@echo "Server PID $$! saved to $(PID_FILE)"
	@echo "Waiting a moment for server to initialize..."
	@sleep 2 # Give server a moment to start before next command

dev-stop: ## Stop the development server by finding and killing the process on port 8080
	@echo "Stopping development server (port 8080)..."
	@PID=$$(lsof -t -i:8080); \
	if [ -n "$$PID" ]; then \
		echo "Killing process $$PID on port 8080"; \
		kill -9 $$PID || echo "Failed to kill process $$PID."; \
	else \
		echo "No process found on port 8080."; \
	fi
	@rm -f $(PID_FILE) # Also remove PID file if it exists

debug: ## Stop, start the dev server, and run API tests
	@echo "Running debug sequence (stop, start, test)..."
	@$(MAKE) dev-stop
	@$(MAKE) dev-start
	@echo "Running API test script..."
	@./test_api.sh

# Development Database Targets
dev-db-up: ## Start the development PostgreSQL container
	@echo "Starting development database..."
	@$(DOCKER) compose -f docker-compose.dev.yml up -d --wait

dev-db-down: ## Stop and remove the development PostgreSQL container and its volumes
	@echo "Stopping development database and removing volumes..."
	@$(DOCKER) compose -f docker-compose.dev.yml down -v # Add -v flag

dev-db-logs: ## View logs for the development PostgreSQL container
	@echo "Showing development database logs..."
	@$(DOCKER) compose -f docker-compose.dev.yml logs -f

dev-db-reset: ## Force reset the development database (stops, removes container and volume)
	@echo "Stopping development database and removing volumes..."
	@$(DOCKER) compose -f docker-compose.dev.yml down -v --remove-orphans
	@echo "Force removing development database volume..."
	@$(DOCKER) volume rm dockerservermangergomcp_pgdata || echo "Volume 'dockerservermangergomcp_pgdata' not found or already removed."
	@echo "Force removing development database container..."
	@$(DOCKER) rm dsm_postgres_dev || echo "Container 'dsm_postgres_dev' not found or already removed."
	@echo "Database reset complete. Use 'make dev-db-up' to restart."


# Docker development environment targets
docker-dev-build: ## Build the development Docker image
	@echo "Building development Docker image..."
	@$(DOCKER) build -t $(DOCKER_DEV_IMAGE) -f Dockerfile.dev .

docker-fmt: docker-dev-build ## Format Go source files using Docker
	@echo "Formatting Go files using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace $(DOCKER_DEV_IMAGE) fmt

docker-lint: docker-dev-build ## Run golangci-lint for code analysis using Docker
	@echo "Running linters using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace $(DOCKER_DEV_IMAGE) lint

docker-security: docker-dev-build ## Run security scans using Docker
	@echo "Running security scans using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace $(DOCKER_DEV_IMAGE) security

docker-tests: docker-dev-build ## Run unit tests with coverage using Docker
	@echo "Running tests using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace -e GITHUB_TOKEN=$(GITHUB_TOKEN) $(DOCKER_DEV_IMAGE) test

docker-coverage: docker-dev-build ## Generate test coverage report using Docker
	@echo "Generating coverage report using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace -e GITHUB_TOKEN=$(GITHUB_TOKEN) $(DOCKER_DEV_IMAGE) coverage

docker-dupl-check: docker-dev-build ## Check for duplicate code using Docker
	@echo "Checking for duplicate code using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace $(DOCKER_DEV_IMAGE) dupl-check

docker-all: docker-dev-build ## Run all checks and tests using Docker
	@echo "Running all checks and tests using Docker..."
	@$(DOCKER) run -v $(CURDIR):/workspace -e GITHUB_TOKEN=$(GITHUB_TOKEN) $(DOCKER_DEV_IMAGE) all dupl-check

docker-shell: docker-dev-build ## Start a shell in the development container
	@echo "Starting shell in development container..."
	@$(DOCKER) run -it -v $(CURDIR):/workspace $(DOCKER_DEV_IMAGE) shell
