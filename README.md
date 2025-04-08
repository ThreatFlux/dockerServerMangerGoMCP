# Docker Server Manager Go MCP
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/threatflux/dockerServerMangerGoMCP/CI)
![GitHub](https://img.shields.io/github/license/threatflux/dockerServerMangerGoMCP)
![GitHub Repo stars](https://img.shields.io/github/stars/threatflux/dockerServerMangerGoMCP?style=social)
![GitHub issues](https://img.shields.io/github/issues/threatflux/dockerServerMangerGoMCP)
![GitHub pull requests](https://img.shields.io/github/issues-pr/threatflux/dockerServerMangerGoMCP)
![GitHub last commit](https://img.shields.io/github/last-commit/threatflux/dockerServerMangerGoMCP)
![GitHub contributors](https://img.shields.io/github/contributors/threatflux/dockerServerMangerGoMCP)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/threatflux/dockerServerMangerGoMCP)

***Note: This project is in early development and may not be fully functional. Use at your own risk.***

Docker Server Manager Go MCP (DSM) is a comprehensive Go-based REST API that provides a powerful and flexible interface for managing Docker containers, images, volumes, networks, and Docker Compose deployments.

## Overview

This project offers a complete solution for Docker management through a web API, featuring JWT authentication, robust CRUD operations, and support for all major Docker functionality. The API supports both PostgreSQL and SQLite databases for persistent storage, managed automatically using GORM.

### Key Features

- **Complete Docker Management**:
  - Container lifecycle management (create, start, stop, remove)
  - Image operations (pull, build, tag, remove)
  - Volume management (create, list, remove)
  - Network operations (create, connect containers, remove)
  - File operations (copy to/from containers)
  - Command execution within containers

- **Docker Compose Support**:
  - Parse and validate Docker Compose YAML files
  - Deploy multi-container applications
  - Track deployment status
  - Scale services up or down
  - Manage resources created by Compose deployments

- **Security**:
  - JWT authentication and authorization
  - Role-based access control
  - Token blacklisting and refresh
  - Password hashing and secure storage

- **API**:
  - RESTful API design with Gin framework
  - Comprehensive API documentation
  - Client SDK for Go applications
  - Swagger/OpenAPI specification

- **Database Support**:
  - PostgreSQL for production environments
  - SQLite for development and testing
  - Automatic schema migrations
  - GORM-based data access layer

## Getting Started

### Prerequisites

- Go 1.24.1 or later
- Docker 24.0.0 or later
- PostgreSQL (for production) or SQLite (for development)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/threatflux/dockerServerMangerGoMCP.git
   cd dockerServerMangerGoMCP
   ```

2. Install dependencies:
   ```
   go mod download
   ```

3. Build the application:
   ```
   make build
   ```

4. Run the server:
   ```
   ./bin/ghactions-updater
   ```

### Docker Deployment

To run the application in Docker:

```
docker-compose up -d
```

## API Documentation

Complete API documentation is available in the `/docs` directory:

- [API Reference](docs/API.md)
- [Authentication Guide](docs/AUTHENTICATION.md)
- [Docker Management](docs/DOCKER.md)
- [Docker Compose](docs/COMPOSE.md)

## Development

For detailed development guidelines, see:

- [Development Guide](docs/DEVELOPMENT.md)

### Building and Testing

```
# Run tests
make test

# Run linting
make lint

# Check for security issues
make security
```

## License

Copyright © 2025 ThreatFlux. All rights reserved.

## Author

Wyatt Roersma
