# Authentication Guide

Docker Server Manager uses a secure JWT (JSON Web Token) based authentication system with role-based access control.

## Authentication Flow

1. **Registration**: Users register with email, password, and name
2. **Login**: Users authenticate with email and password to receive tokens
3. **Token Usage**: Access token is included in requests as Bearer token
4. **Token Refresh**: Refresh token can be used to generate new tokens
5. **Logout**: Tokens can be invalidated

## Token Types

### Access Token

- Used for authenticating API requests
- Short-lived (default: 60 minutes)
- Contains user ID, roles, and other claims

### Refresh Token

- Used to obtain new access tokens
- Longer-lived (default: 24 hours)
- Stored in secure token store

## User Registration

To register a new user, send a POST request to `/api/auth/register`:

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "User Name"
}
```

Password requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

The first user registered automatically receives admin privileges.

## Authentication

To authenticate, send a POST request to `/api/auth/login`:

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

The response includes the tokens:

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

## Using Tokens

Include the access token in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Token Refresh

To refresh tokens, send a POST request to `/api/auth/refresh`:

```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

The response includes new access and refresh tokens.

## Logout

To invalidate tokens, send a POST request to `/api/auth/logout` with the access token in the `Authorization` header.

## Role-Based Access Control

Users can have multiple roles that determine their permissions:

### User Role

- Basic role assigned to all users
- Can view and manage their own resources
- Limited access to Docker operations

### Admin Role

- Full access to all resources and operations
- Can manage users and configurations
- Unrestricted Docker operations

### Custom Roles

Additional roles can be defined as needed for specific access control requirements.

## Role-Based Endpoint Access

API endpoints are protected based on required roles:

- `/api/auth/*`: Accessible to all authenticated users
- `/api/containers/*`: Requires `user` role
- `/api/images/*`: Requires `user` role
- `/api/volumes/*`: Requires `user` role
- `/api/networks/*`: Requires `user` role
- `/api/compose/*`: Requires `user` role
- `/api/admin/*`: Requires `admin` role

## Security Considerations

### Token Storage

- Store tokens securely on the client side
- Access tokens can be stored in memory
- Refresh tokens should be stored in secure HTTP-only cookies or secure storage

### Token Expiry

- Access tokens have a short lifespan to limit the impact of token theft
- Refresh tokens have a longer lifespan but can be revoked

### Token Revocation

Tokens can be revoked in several ways:

1. User logout
2. Admin revocation
3. User password change
4. Security breach detection

### Password Security

Passwords are securely hashed using bcrypt with appropriate cost factor to resist brute force attacks.

## User Profile Management

### Getting Current User

To get the current user profile, send a GET request to `/api/auth/me` with the access token in the `Authorization` header.

### Updating User Profile

To update the user profile, send a PUT request to `/api/auth/me`:

```json
{
  "name": "Updated Name",
  "email": "newemail@example.com"
}
```

### Changing Password

To change the password, send a POST request to `/api/auth/password`:

```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewPassword123!"
}
```

## API Endpoint Security

All API endpoints that modify resources require appropriate authentication and authorization. The server implements:

1. Input validation
2. Rate limiting
3. CORS protection
4. Token validation
5. Role checking

## Advanced Configuration

The authentication system can be configured via environment variables or configuration files:

```yaml
auth:
  jwt_secret: "your-secret-key"
  token_expiry: "60m"
  refresh_expiry: "24h"
  allow_registration: true
  password_min_length: 8
  password_require_uppercase: true
  password_require_lowercase: true
  password_require_number: true
  password_require_special: true
```

## Troubleshooting

### Invalid Token

If you receive a 401 Unauthorized response with an "Invalid token" error, your token may have expired or been revoked. Try refreshing your token.

### Token Expired

If your access token has expired, use the refresh token to obtain a new one.

### Invalid Refresh Token

If your refresh token is invalid or expired, you'll need to log in again.

### Rate Limiting

If you receive a 429 Too Many Requests response, you have exceeded the rate limit. Wait before making more requests.

### Missing Permissions

If you receive a 403 Forbidden response, you do not have the required role for the requested operation.
