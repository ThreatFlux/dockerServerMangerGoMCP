# Docker Server Manager API Documentation

This document provides a comprehensive reference for all API endpoints available in the Docker Server Manager.

## Base URL

All API endpoints are prefixed with `/api`.

## Authentication

Most API endpoints require authentication. Authentication is performed using JWT (JSON Web Token) in the `Authorization` header.

Example:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Authentication Endpoints

#### Register a New User

```
POST /api/auth/register
```

Request body:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "User Name"
}
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "expires_at": "2025-01-01T12:00:00Z",
  "user_id": 1,
  "roles": ["user", "admin"]
}
```

#### Login

```
POST /api/auth/login
```

Request body:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

Response: Same as register endpoint.

#### Refresh Token

```
POST /api/auth/refresh
```

Request body:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

Response: Same as login endpoint.

#### Logout

```
POST /api/auth/logout
```

No request body needed, but requires Authorization header.

Response: 204 No Content

#### Get Current User

```
GET /api/auth/me
```

Response:
```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "User Name",
  "roles": ["user", "admin"],
  "last_login": "2025-01-01T12:00:00Z",
  "email_verified": true,
  "active": true,
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T12:00:00Z"
}
```

#### Update Current User

```
PUT /api/auth/me
```

Request body:
```json
{
  "name": "Updated Name",
  "email": "newemail@example.com"
}
```

Response: Updated user object.

#### Change Password

```
POST /api/auth/password
```

Request body:
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewPassword123!"
}
```

Response: 204 No Content

## Container Management

### List Containers

```
GET /api/containers
```

Query parameters:
- `all`: Include stopped containers (default: false)
- `limit`: Limit number of containers returned
- `offset`: Offset for pagination
- `filters`: JSON-encoded filters

Response:
```json
{
  "containers": [
    {
      "id": "container1",
      "names": ["/web-app"],
      "image": "nginx:latest",
      "image_id": "sha256:abc123...",
      "command": "nginx -g 'daemon off;'",
      "created": 1630000000,
      "state": "running",
      "status": "Up 2 days",
      "ports": [
        {
          "ip": "0.0.0.0",
          "private_port": 80,
          "public_port": 8080,
          "type": "tcp"
        }
      ],
      "labels": {
        "com.example.description": "Web application"
      },
      "size_rw": 0,
      "size_root_fs": 0,
      "host_config": {
        "network_mode": "bridge"
      },
      "network_settings": {
        "networks": {
          "bridge": {
            "ip_address": "172.17.0.2",
            "gateway": "172.17.0.1",
            "ip_prefix_len": 16
          }
        }
      },
      "mounts": [
        {
          "type": "bind",
          "source": "/var/www/html",
          "destination": "/usr/share/nginx/html"
        }
      ]
    }
  ],
  "total": 1
}
```

### Get Container

```
GET /api/containers/{id}
```

Response: Detailed container object.

### Create Container

```
POST /api/containers
```

Request body:
```json
{
  "name": "web-app",
  "image": "nginx:latest",
  "exposed_ports": {
    "80/tcp": {}
  },
  "host_config": {
    "port_bindings": {
      "80/tcp": [
        {
          "host_ip": "0.0.0.0",
          "host_port": "8080"
        }
      ]
    },
    "restart_policy": {
      "name": "always"
    }
  },
  "env": [
    "NGINX_HOST=example.com",
    "NGINX_PORT=80"
  ]
}
```

Response:
```json
{
  "id": "container1",
  "warnings": []
}
```

### Start Container

```
POST /api/containers/{id}/start
```

Response:
```json
{
  "id": "container1",
  "state": "running"
}
```

### Stop Container

```
POST /api/containers/{id}/stop
```

Optional query parameters:
- `t`: Timeout in seconds before killing the container

Response:
```json
{
  "id": "container1",
  "state": "exited"
}
```

### Restart Container

```
POST /api/containers/{id}/restart
```

Optional query parameters:
- `t`: Timeout in seconds before killing the container

Response:
```json
{
  "id": "container1",
  "state": "running"
}
```

### Remove Container

```
DELETE /api/containers/{id}
```

Optional query parameters:
- `v`: Remove volumes (default: false)
- `force`: Force removal (default: false)

Response: 204 No Content

### Container Logs

```
GET /api/containers/{id}/logs
```

Query parameters:
- `follow`: Follow log output (default: false)
- `stdout`: Show stdout logs (default: true)
- `stderr`: Show stderr logs (default: true)
- `since`: Show logs since timestamp (default: 0)
- `until`: Show logs until timestamp (default: now)
- `timestamps`: Show timestamps (default: false)
- `tail`: Number of lines to show from the end (default: "all")

Response: Stream of log data

### Container Stats

```
GET /api/containers/{id}/stats
```

Query parameters:
- `stream`: Stream stats data (default: false)

Response:
```json
{
  "id": "container1",
  "name": "/web-app",
  "cpu_stats": {
    "cpu_usage": {
      "total_usage": 1000000000,
      "percpu_usage": [500000000, 500000000],
      "usage_in_kernelmode": 100000000,
      "usage_in_usermode": 900000000
    },
    "system_cpu_usage": 10000000000,
    "online_cpus": 2,
    "throttling_data": {
      "periods": 0,
      "throttled_periods": 0,
      "throttled_time": 0
    }
  },
  "memory_stats": {
    "usage": 104857600,
    "max_usage": 209715200,
    "stats": {
      "active_anon": 104857600,
      "active_file": 0,
      "cache": 0,
      "dirty": 0,
      "inactive_anon": 0,
      "inactive_file": 0,
      "mapped_file": 0,
      "pgfault": 2000,
      "pgmajfault": 0,
      "pgpgin": 1000,
      "pgpgout": 500,
      "rss": 104857600,
      "rss_huge": 0,
      "total_active_anon": 104857600,
      "total_active_file": 0,
      "total_cache": 0,
      "total_dirty": 0,
      "total_inactive_anon": 0,
      "total_inactive_file": 0,
      "total_mapped_file": 0,
      "total_pgfault": 2000,
      "total_pgmajfault": 0,
      "total_pgpgin": 1000,
      "total_pgpgout": 500,
      "total_rss": 104857600,
      "total_rss_huge": 0,
      "total_unevictable": 0,
      "total_writeback": 0,
      "unevictable": 0,
      "writeback": 0
    },
    "limit": 2147483648
  },
  "networks": {
    "eth0": {
      "rx_bytes": 1000000,
      "rx_packets": 10000,
      "rx_errors": 0,
      "rx_dropped": 0,
      "tx_bytes": 500000,
      "tx_packets": 5000,
      "tx_errors": 0,
      "tx_dropped": 0
    }
  },
  "blkio_stats": {
    "io_service_bytes_recursive": [
      {
        "major": 8,
        "minor": 0,
        "op": "read",
        "value": 100000
      },
      {
        "major": 8,
        "minor": 0,
        "op": "write",
        "value": 50000
      }
    ]
  }
}
```

### Execute Command in Container

```
POST /api/containers/{id}/exec
```

Request body:
```json
{
  "cmd": ["echo", "hello world"],
  "attach_stdin": false,
  "attach_stdout": true,
  "attach_stderr": true,
  "tty": false
}
```

Response:
```json
{
  "id": "exec123",
  "output": "hello world\n"
}
```

### Copy Files to Container

```
POST /api/containers/{id}/copy-to
```

Request body: Multipart form with file and path fields

Response:
```json
{
  "message": "Successfully copied file to container"
}
```

### Copy Files from Container

```
POST /api/containers/{id}/copy-from
```

Request body:
```json
{
  "path": "/etc/nginx/nginx.conf"
}
```

Response: File download

## Image Management

### List Images

```
GET /api/images
```

Response:
```json
{
  "images": [
    {
      "id": "sha256:abc123...",
      "repo_tags": ["nginx:latest"],
      "repo_digests": ["nginx@sha256:def456..."],
      "created": 1630000000,
      "size": 133333333,
      "shared_size": 0,
      "virtual_size": 133333333,
      "labels": {},
      "containers": 1
    }
  ],
  "total": 1
}
```

### Get Image

```
GET /api/images/{id}
```

Response: Detailed image object.

### Pull Image

```
POST /api/images/pull
```

Request body:
```json
{
  "image": "nginx",
  "tag": "latest"
}
```

Response:
```json
{
  "id": "sha256:abc123...",
  "tags": ["nginx:latest"],
  "status": "Image pulled successfully"
}
```

### Build Image

```
POST /api/images/build
```

Request body: Multipart form with Dockerfile and build context

Response:
```json
{
  "id": "sha256:abc123...",
  "tags": ["myapp:latest"],
  "status": "Image built successfully"
}
```

### Tag Image

```
POST /api/images/{id}/tag
```

Request body:
```json
{
  "repo": "myregistry/myapp",
  "tag": "v1.0"
}
```

Response:
```json
{
  "id": "sha256:abc123...",
  "repo": "myregistry/myapp",
  "tag": "v1.0"
}
```

### Remove Image

```
DELETE /api/images/{id}
```

Optional query parameters:
- `force`: Force removal (default: false)
- `noprune`: Do not delete untagged parents (default: false)

Response: 204 No Content

## Volume Management

### List Volumes

```
GET /api/volumes
```

Response:
```json
{
  "volumes": [
    {
      "name": "my-volume",
      "driver": "local",
      "mountpoint": "/var/lib/docker_test/volumes/my-volume/_data",
      "created_at": "2025-01-01T00:00:00Z",
      "status": {},
      "labels": {
        "com.example.description": "My data volume"
      },
      "scope": "local",
      "options": {}
    }
  ],
  "total": 1
}
```

### Get Volume

```
GET /api/volumes/{name}
```

Response: Detailed volume object.

### Create Volume

```
POST /api/volumes
```

Request body:
```json
{
  "name": "my-volume",
  "driver": "local",
  "driver_opts": {
    "type": "nfs",
    "device": ":/path/to/dir",
    "o": "addr=1.2.3.4,rw"
  },
  "labels": {
    "com.example.description": "My data volume"
  }
}
```

Response:
```json
{
  "name": "my-volume",
  "driver": "local",
  "mountpoint": "/var/lib/docker_test/volumes/my-volume/_data",
  "created_at": "2025-01-01T00:00:00Z",
  "status": {},
  "labels": {
    "com.example.description": "My data volume"
  },
  "scope": "local",
  "options": {
    "type": "nfs",
    "device": ":/path/to/dir",
    "o": "addr=1.2.3.4,rw"
  }
}
```

### Remove Volume

```
DELETE /api/volumes/{name}
```

Optional query parameters:
- `force`: Force removal (default: false)

Response: 204 No Content

### Prune Volumes

```
POST /api/volumes/prune
```

Response:
```json
{
  "volumes_deleted": ["unused-volume1", "unused-volume2"],
  "space_reclaimed": 12345678
}
```

## Network Management

### List Networks

```
GET /api/networks
```

Response:
```json
{
  "networks": [
    {
      "id": "network1",
      "name": "bridge",
      "created": "2025-01-01T00:00:00Z",
      "scope": "local",
      "driver": "bridge",
      "enable_ipv6": false,
      "ipam": {
        "driver": "default",
        "config": [
          {
            "subnet": "172.17.0.0/16",
            "gateway": "172.17.0.1"
          }
        ],
        "options": {}
      },
      "internal": false,
      "attachable": false,
      "ingress": false,
      "containers": {
        "container1": {
          "name": "web-app",
          "endpoint_id": "endpoint1",
          "mac_address": "02:42:ac:11:00:02",
          "ipv4_address": "172.17.0.2/16",
          "ipv6_address": ""
        }
      },
      "options": {},
      "labels": {}
    }
  ],
  "total": 1
}
```

### Get Network

```
GET /api/networks/{id}
```

Response: Detailed network object.

### Create Network

```
POST /api/networks
```

Request body:
```json
{
  "name": "my-network",
  "driver": "bridge",
  "ipam": {
    "driver": "default",
    "config": [
      {
        "subnet": "172.20.0.0/16",
        "gateway": "172.20.0.1"
      }
    ]
  },
  "options": {
    "com.docker.network.bridge.default_bridge": "false",
    "com.docker.network.bridge.enable_icc": "true"
  },
  "labels": {
    "com.example.description": "My custom network"
  }
}
```

Response:
```json
{
  "id": "network2",
  "name": "my-network"
}
```

### Remove Network

```
DELETE /api/networks/{id}
```

Response: 204 No Content

### Connect Container to Network

```
POST /api/networks/{id}/connect
```

Request body:
```json
{
  "container": "container1",
  "endpoint_config": {
    "ipv4_address": "172.20.0.2",
    "aliases": ["web"]
  }
}
```

Response: 204 No Content

### Disconnect Container from Network

```
POST /api/networks/{id}/disconnect
```

Request body:
```json
{
  "container": "container1",
  "force": false
}
```

Response: 204 No Content

## Docker Compose Management

### Validate Compose File

```
POST /api/compose/validate
```

Request body: Multipart form with compose file

Response:
```json
{
  "valid": true,
  "services": [
    {
      "name": "web",
      "image": "nginx:alpine",
      "ports": ["8080:80"]
    },
    {
      "name": "db",
      "image": "postgres:12",
      "environment": [
        "POSTGRES_PASSWORD=password",
        "POSTGRES_USER=user",
        "POSTGRES_DB=mydb"
      ]
    }
  ],
  "volumes": [
    {
      "name": "postgres-data",
      "driver": "local"
    }
  ],
  "networks": []
}
```

### Deploy Compose Stack

```
POST /api/compose/deploy
```

Request body: Multipart form with compose file

Response:
```json
{
  "deployment_id": "deployment1",
  "message": "Deployment started successfully",
  "status_url": "/api/compose/deployment1/status"
}
```

### Get Deployment Status

```
GET /api/compose/{deployment_id}/status
```

Response:
```json
{
  "deployment_id": "deployment1",
  "status": "running",
  "services": [
    {
      "name": "web",
      "status": "running",
      "containers": [
        {
          "id": "container1",
          "name": "deployment1-web-1",
          "status": "running"
        }
      ]
    },
    {
      "name": "db",
      "status": "running",
      "containers": [
        {
          "id": "container2",
          "name": "deployment1-db-1",
          "status": "running"
        }
      ]
    }
  ],
  "start_time": "2025-01-01T00:00:00Z",
  "elapsed_time": "1h 30m 15s"
}
```

### Get Service Status

```
GET /api/compose/{deployment_id}/services/{service_name}
```

Response:
```json
{
  "name": "web",
  "status": "running",
  "containers": [
    {
      "id": "container1",
      "name": "deployment1-web-1",
      "status": "running",
      "created": "2025-01-01T00:00:00Z",
      "ports": [
        {
          "internal": 80,
          "external": 8080,
          "protocol": "tcp"
        }
      ]
    }
  ],
  "image": "nginx:alpine",
  "ports": ["8080:80"],
  "volumes": [],
  "depends_on": ["db"]
}
```

### Scale Service

```
POST /api/compose/{deployment_id}/scale
```

Request body:
```json
{
  "service": "web",
  "replicas": 3
}
```

Response:
```json
{
  "service": "web",
  "replicas": 3,
  "message": "Service scaled successfully"
}
```

### Stop Deployment

```
POST /api/compose/{deployment_id}/stop
```

Response:
```json
{
  "deployment_id": "deployment1",
  "message": "Deployment stopped successfully"
}
```

### Start Deployment

```
POST /api/compose/{deployment_id}/start
```

Response:
```json
{
  "deployment_id": "deployment1",
  "message": "Deployment started successfully"
}
```

### Remove Deployment

```
DELETE /api/compose/{deployment_id}
```

Optional query parameters:
- `volumes`: Remove volumes (default: false)

Response:
```json
{
  "deployment_id": "deployment1",
  "message": "Deployment removed successfully"
}
```

## Health Check

```
GET /api/health
```

Response:
```json
{
  "status": "ok",
  "timestamp": "2025-01-01T00:00:00Z",
  "version": "1.0.0",
  "services": {
    "database": "ok",
    "docker": "ok"
  }
}
```

## Error Responses

All API endpoints follow a consistent error response format:

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": {}
}
```

Common error codes:
- `INVALID_REQUEST`: Invalid request parameters
- `NOT_FOUND`: Resource not found
- `UNAUTHORIZED`: Authentication required
- `FORBIDDEN`: Insufficient permissions
- `INTERNAL_ERROR`: Internal server error
- `DOCKER_ERROR`: Docker engine error

For validation errors, the response includes a list of validation errors:

```json
{
  "error": "Invalid request parameters",
  "code": "VALIDATION_ERROR",
  "validationErrors": [
    {
      "field": "name",
      "code": "REQUIRED",
      "message": "Name is required",
      "value": ""
    }
  ]
}
```
