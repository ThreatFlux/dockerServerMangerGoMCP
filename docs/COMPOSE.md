# Docker Compose Management

This document provides a comprehensive guide to using the Docker Compose management features of the Docker Server Manager.

## Overview

Docker Server Manager provides a complete REST API for working with Docker Compose deployments. It supports uploading, validating, deploying, and managing Compose applications.

## Compose File Support

The API supports Docker Compose files with the following specifications:

- Version 3.x (recommended)
- Version 2.x (supported)
- Version 1.x (limited support)

## Compose Management Workflow

1. **Upload & Validate**: Upload and validate Compose file
2. **Deploy**: Create and start services defined in Compose file
3. **Monitor**: Track deployment status and service health
4. **Scale**: Adjust service replicas as needed
5. **Update**: Modify deployment configurations
6. **Stop/Start**: Control deployment lifecycle
7. **Remove**: Clean up deployment when no longer needed

## Validating Compose Files

Before deploying, you can validate a Compose file to check for issues:

```
POST /api/compose/validate
```

Upload the Compose file using a multipart form with the file field named "file".

The response includes validation results and parsed services:

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

If the Compose file is invalid, the response includes error details:

```json
{
  "valid": false,
  "error": "Service 'web' contains an invalid port mapping: '8080/80'",
  "line": 5,
  "column": 7
}
```

## Deploying Compose Stacks

To deploy a Compose stack:

```
POST /api/compose/deploy
```

Upload the Compose file using a multipart form with the file field named "file".

Optional form fields:
- `name`: Custom name for the deployment (default: directory name or generated ID)
- `environment_file`: .env file for variable substitution
- `pull_images`: Whether to pull images before starting (true/false, default: true)

The response includes a deployment ID and status URL:

```json
{
  "deployment_id": "webapp-12345",
  "message": "Deployment started successfully",
  "status_url": "/api/compose/webapp-12345/status"
}
```

## Monitoring Deployment Status

Check the status of a deployment:

```
GET /api/compose/{deployment_id}/status
```

The response includes deployment status and service details:

```json
{
  "deployment_id": "webapp-12345",
  "name": "webapp",
  "status": "running",
  "services": [
    {
      "name": "web",
      "status": "running",
      "replicas": 2,
      "running_replicas": 2,
      "containers": [
        {
          "id": "container1",
          "name": "webapp-web-1",
          "status": "running",
          "health": "healthy"
        },
        {
          "id": "container2",
          "name": "webapp-web-2",
          "status": "running",
          "health": "healthy"
        }
      ]
    },
    {
      "name": "db",
      "status": "running",
      "replicas": 1,
      "running_replicas": 1,
      "containers": [
        {
          "id": "container3",
          "name": "webapp-db-1",
          "status": "running",
          "health": "healthy"
        }
      ]
    }
  ],
  "created_at": "2025-01-01T00:00:00Z",
  "start_time": "2025-01-01T00:00:05Z",
  "elapsed_time": "1h 30m 15s"
}
```

Possible deployment status values:
- `starting`: Initial deployment in progress
- `running`: All services running
- `partially_running`: Some services running, some failed
- `stopped`: All services stopped
- `failed`: Deployment failed
- `removed`: Deployment removed

## Managing Individual Services

### Get Service Details

Get detailed information about a specific service:

```
GET /api/compose/{deployment_id}/services/{service_name}
```

The response includes service configuration and status:

```json
{
  "name": "web",
  "status": "running",
  "replicas": 2,
  "running_replicas": 2,
  "containers": [
    {
      "id": "container1",
      "name": "webapp-web-1",
      "status": "running",
      "created": "2025-01-01T00:00:00Z",
      "started": "2025-01-01T00:00:05Z",
      "health": "healthy",
      "ports": [
        {
          "internal": 80,
          "external": 8080,
          "protocol": "tcp"
        }
      ],
      "ip_addresses": {
        "bridge": "172.17.0.2"
      }
    },
    {
      "id": "container2",
      "name": "webapp-web-2",
      "status": "running",
      "created": "2025-01-01T00:00:00Z",
      "started": "2025-01-01T00:00:05Z",
      "health": "healthy",
      "ports": [
        {
          "internal": 80,
          "external": 8081,
          "protocol": "tcp"
        }
      ],
      "ip_addresses": {
        "bridge": "172.17.0.3"
      }
    }
  ],
  "image": "nginx:alpine",
  "ports": ["8080:80"],
  "volumes": [],
  "environment": [],
  "depends_on": ["db"],
  "restart_policy": "unless-stopped",
  "deploy": {
    "replicas": 2,
    "resources": {
      "limits": {
        "cpus": "0.5",
        "memory": "512M"
      }
    }
  }
}
```

### Scale Service

Adjust the number of replicas for a service:

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
  "previous_replicas": 2,
  "message": "Service scaled successfully"
}
```

### Restart Service

Restart all containers in a service:

```
POST /api/compose/{deployment_id}/services/{service_name}/restart
```

Response:
```json
{
  "service": "web",
  "message": "Service restarted successfully"
}
```

### Pull and Update Service

Pull the latest image and update a service:

```
POST /api/compose/{deployment_id}/services/{service_name}/update
```

Optional request body:
```json
{
  "force_recreate": true,
  "pull_image": true
}
```

Response:
```json
{
  "service": "web",
  "message": "Service updated successfully"
}
```

## Managing Deployments

### Stop Deployment

Stop all services in a deployment:

```
POST /api/compose/{deployment_id}/stop
```

Response:
```json
{
  "deployment_id": "webapp-12345",
  "message": "Deployment stopped successfully"
}
```

### Start Deployment

Start all services in a previously stopped deployment:

```
POST /api/compose/{deployment_id}/start
```

Response:
```json
{
  "deployment_id": "webapp-12345",
  "message": "Deployment started successfully"
}
```

### Restart Deployment

Restart all services in a deployment:

```
POST /api/compose/{deployment_id}/restart
```

Response:
```json
{
  "deployment_id": "webapp-12345",
  "message": "Deployment restarted successfully"
}
```

### Remove Deployment

Remove a deployment and its resources:

```
DELETE /api/compose/{deployment_id}
```

Optional query parameters:
- `volumes`: Remove associated volumes (default: false)
- `images`: Remove associated images (default: false)

Response:
```json
{
  "deployment_id": "webapp-12345",
  "message": "Deployment removed successfully",
  "removed_resources": {
    "containers": 3,
    "networks": 1,
    "volumes": 0
  }
}
```

## Deployment Events

Get deployment events (actions and status changes):

```
GET /api/compose/{deployment_id}/events
```

Optional query parameters:
- `limit`: Maximum number of events to return
- `since`: Return events since timestamp

Response:
```json
{
  "deployment_id": "webapp-12345",
  "events": [
    {
      "timestamp": "2025-01-01T00:00:00Z",
      "type": "DEPLOYMENT_CREATED",
      "message": "Deployment created",
      "details": {
        "services": ["web", "db"]
      }
    },
    {
      "timestamp": "2025-01-01T00:00:02Z",
      "type": "PULL_IMAGE",
      "message": "Pulling image nginx:alpine",
      "service": "web"
    },
    {
      "timestamp": "2025-01-01T00:00:05Z",
      "type": "CONTAINER_CREATED",
      "message": "Container created",
      "service": "web",
      "container": "webapp-web-1"
    },
    {
      "timestamp": "2025-01-01T00:00:07Z",
      "type": "CONTAINER_STARTED",
      "message": "Container started",
      "service": "web",
      "container": "webapp-web-1"
    }
  ],
  "count": 4,
  "has_more": true
}
```

## Deployment Logs

Get logs from all containers in a deployment:

```
GET /api/compose/{deployment_id}/logs
```

Optional query parameters:
- `follow`: Follow log output
- `timestamps`: Include timestamps
- `tail`: Number of lines to show from the end
- `since`: Show logs since timestamp
- `services`: Comma-separated list of services to include

Response: Stream of log data with service/container prefixes

## Configuration Overrides

When deploying a Compose file, you can provide overrides for certain configurations:

```
POST /api/compose/deploy
```

In addition to the Compose file, you can include these form fields:
- `overrides`: JSON object with configuration overrides
- `environment`: JSON object with environment variable overrides

Example overrides:
```json
{
  "services": {
    "web": {
      "environment": {
        "DEBUG": "true"
      },
      "ports": ["8081:80"]
    }
  },
  "volumes": {
    "data-volume": {
      "driver_opts": {
        "size": "20G"
      }
    }
  }
}
```

## Best Practices

### Compose File Structure

- Use version 3.x format
- Define service dependencies
- Set appropriate resource limits
- Use named volumes for persistent data
- Define custom networks
- Add health checks

Example:
```yaml
version: '3.8'

services:
  web:
    image: nginx:alpine
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "8080:80"
    volumes:
      - ./html:/usr/share/nginx/html
    environment:
      - NGINX_HOST=example.com
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 5s
    restart: unless-stopped
    networks:
      - frontend
      - backend

  db:
    image: postgres:12
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=mydb
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
    restart: unless-stopped
    networks:
      - backend

volumes:
  postgres-data:

networks:
  frontend:
  backend:
    internal: true
```

### Deployment Strategies

#### Development

For development environments:
- Mount local code directories as volumes
- Enable environment variables for debugging
- Use appropriate port mappings

#### Production

For production environments:
- Use specific image tags, not `latest`
- Set appropriate resource limits
- Implement health checks
- Configure restart policies
- Define update strategies

### Monitoring and Maintenance

- Regularly check deployment status
- Monitor service health
- Review logs for issues
- Update images periodically
- Scale services based on load
- Back up persistent data

## Security Considerations

### Network Security

- Use internal networks for inter-service communication
- Expose only necessary ports
- Use secure passwords and secrets

### Resource Limits

- Set appropriate memory and CPU limits
- Implement disk usage quotas
- Monitor resource usage

### Image Security

- Use trusted images
- Scan images for vulnerabilities
- Keep images updated

### Access Control

- Implement role-based access to Compose operations
- Restrict deployment privileges
- Audit deployment actions
