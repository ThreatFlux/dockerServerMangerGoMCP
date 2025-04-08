# Docker Management

This document provides a comprehensive guide to using the Docker management features of the Docker Server Manager.

## Overview

Docker Server Manager provides a complete REST API for managing Docker containers, images, volumes, and networks. It supports all core Docker operations, with a focus on security and manageability.

## Docker Connection Configuration

The Docker Server Manager can connect to Docker in several ways:

### Local Docker Socket

Connect to Docker on the same machine:

```yaml
docker:
  host: "unix:///var/run/docker_test.sock"
```

### Remote Docker Host

Connect to a remote Docker host:

```yaml
docker:
  host: "tcp://remote-docker_test-host:2375"
```

### Remote Docker Host with TLS

Connect to a remote Docker host with TLS:

```yaml
docker:
  host: "tcp://remote-docker_test-host:2376"
  tls_verify: true
  cert_path: "/path/to/certs"
  ca_file: "ca.pem"
  key_file: "key.pem"
  cert_file: "cert.pem"
```

## Container Management

### Container Lifecycle

1. **Create**: Define container configuration
2. **Start**: Run a created container
3. **Stop**: Stop a running container
4. **Restart**: Restart a container
5. **Remove**: Delete a container

### Creating Containers

Create containers with various configuration options:

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
    },
    "mounts": [
      {
        "type": "bind",
        "source": "/path/on/host",
        "target": "/path/in/container",
        "read_only": false
      },
      {
        "type": "volume",
        "source": "data-volume",
        "target": "/data",
        "read_only": false
      }
    ]
  },
  "env": [
    "ENVIRONMENT=production",
    "DEBUG=false"
  ],
  "cmd": ["nginx", "-g", "daemon off;"],
  "working_dir": "/usr/share/nginx/html",
  "user": "nginx",
  "labels": {
    "com.example.description": "Web application",
    "com.example.version": "1.0"
  }
}
```

### Starting Containers

Start a created container:

```
POST /api/containers/{id}/start
```

### Stopping Containers

Stop a running container:

```
POST /api/containers/{id}/stop
```

Optional parameters:
- `t`: Timeout in seconds before killing the container

### Restarting Containers

Restart a container:

```
POST /api/containers/{id}/restart
```

Optional parameters:
- `t`: Timeout in seconds before killing the container

### Removing Containers

Remove a container:

```
DELETE /api/containers/{id}
```

Optional parameters:
- `v`: Remove volumes
- `force`: Force removal of running containers

### Container File Operations

#### Copy Files to Container

Copy files from host to container:

```
POST /api/containers/{id}/copy-to
```

Upload files using a multipart form, including:
- `file`: The file to upload
- `path`: The path in the container

#### Copy Files from Container

Copy files from container to host:

```
POST /api/containers/{id}/copy-from
```

Request body:
```json
{
  "path": "/path/in/container/file.txt"
}
```

### Command Execution

Execute commands in containers:

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
  "tty": false,
  "env": ["FOO=bar"]
}
```

### Accessing Container Logs

Get container logs:

```
GET /api/containers/{id}/logs
```

Optional parameters:
- `follow`: Follow log output
- `stdout`: Show stdout logs
- `stderr`: Show stderr logs
- `since`: Show logs since timestamp
- `until`: Show logs until timestamp
- `timestamps`: Show timestamps
- `tail`: Number of lines to show from the end

### Container Resource Monitoring

Monitor container resource usage:

```
GET /api/containers/{id}/stats
```

Optional parameters:
- `stream`: Stream stats data continuously

## Image Management

### Listing Images

List all available images:

```
GET /api/images
```

Optional parameters:
- `all`: Show all images
- `filters`: Filter images (JSON format)

### Pulling Images

Pull images from registry:

```
POST /api/images/pull
```

Request body:
```json
{
  "image": "nginx",
  "tag": "latest",
  "registry": "docker_test.io"
}
```

### Building Images

Build images from Dockerfile:

```
POST /api/images/build
```

Upload a Dockerfile and build context using a multipart form, including:
- `dockerfile`: The Dockerfile
- `tag`: Tag for the built image

### Tagging Images

Tag an existing image:

```
POST /api/images/{id}/tag
```

Request body:
```json
{
  "repo": "myapp",
  "tag": "v1.0"
}
```

### Removing Images

Remove an image:

```
DELETE /api/images/{id}
```

Optional parameters:
- `force`: Force removal
- `noprune`: Do not delete untagged parents

## Volume Management

### Creating Volumes

Create Docker volumes:

```
POST /api/volumes
```

Request body:
```json
{
  "name": "data-volume",
  "driver": "local",
  "driver_opts": {
    "type": "nfs",
    "device": ":/path/to/dir",
    "o": "addr=1.2.3.4,rw"
  },
  "labels": {
    "com.example.description": "Data volume"
  }
}
```

### Listing Volumes

List all volumes:

```
GET /api/volumes
```

### Removing Volumes

Remove a volume:

```
DELETE /api/volumes/{name}
```

Optional parameters:
- `force`: Force removal even if used by containers

### Pruning Volumes

Remove all unused volumes:

```
POST /api/volumes/prune
```

## Network Management

### Creating Networks

Create Docker networks:

```
POST /api/networks
```

Request body:
```json
{
  "name": "app-network",
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
    "com.example.description": "Application network"
  }
}
```

### Listing Networks

List all networks:

```
GET /api/networks
```

### Connecting Containers to Network

Connect a container to a network:

```
POST /api/networks/{id}/connect
```

Request body:
```json
{
  "container": "web-app",
  "endpoint_config": {
    "ipv4_address": "172.20.0.2",
    "aliases": ["web"]
  }
}
```

### Disconnecting Containers from Network

Disconnect a container from a network:

```
POST /api/networks/{id}/disconnect
```

Request body:
```json
{
  "container": "web-app",
  "force": false
}
```

### Removing Networks

Remove a network:

```
DELETE /api/networks/{id}
```

## Security Features

Docker Server Manager implements several security features for Docker operations:

### Security Defaults

- Containers run without special privileges
- Default security profiles applied
- Resource limits enforced

### Container Security Scanning

Containers and images can be scanned for vulnerabilities:

```
POST /api/containers/{id}/scan
```

```
POST /api/images/{id}/scan
```

Response includes:
- Vulnerabilities found
- Severity levels
- Recommendations

### Resource Controls

Containers can be created with resource limits:

```json
{
  "name": "limited-container",
  "image": "nginx:latest",
  "host_config": {
    "memory": 512000000,
    "memory_swap": 1024000000,
    "cpu_shares": 512,
    "cpu_period": 100000,
    "cpu_quota": 50000
  }
}
```

### Mount Security

Mount paths are validated to prevent security issues:

- No sensitive host paths allowed
- Appropriate permissions applied
- Read-only mounts when possible

### Capability Control

Container capabilities are limited by default:

```json
{
  "host_config": {
    "cap_drop": ["ALL"],
    "cap_add": ["NET_BIND_SERVICE"]
  }
}
```

## Best Practices

### Container Organization

- Use meaningful container names
- Apply labels for organization
- Group containers using networks

### Resource Management

- Set appropriate resource limits
- Monitor container resource usage
- Implement alerts for resource issues

### Image Management

- Use specific image tags, not `latest`
- Regularly update images
- Scan images for vulnerabilities

### Volume Management

- Use named volumes for persistent data
- Implement backup strategies
- Clean up unused volumes

### Network Management

- Create dedicated networks for applications
- Use internal networks when possible
- Implement proper network segmentation
