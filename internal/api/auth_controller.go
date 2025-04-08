package api

import (
	"context"
	"errors" // Added for error checking
	"fmt"
	"net/http"
	"strconv" // Added for parsing user ID
	"strings" // Added for CreateUser default logic and error checking
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/auth"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/database/repositories"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/middleware" // Added import
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
	"github.com/threatflux/dockerServerMangerGoMCP/internal/utils"
	"gorm.io/gorm" // Added for gorm errors
)

// AuthController handles authentication-related requests
type AuthController struct {
	authService   auth.Service
	userRepo      repositories.UserRepository // Use the interface type
	logger        *logrus.Logger
	tokenExpiry   time.Duration
	refreshExpiry time.Duration
}

// NewAuthController creates a new AuthController
func NewAuthController(
	authService auth.Service,
	userRepo repositories.UserRepository, // Expect the interface type
	logger *logrus.Logger,
	tokenExpiry time.Duration,
	refreshExpiry time.Duration,
) *AuthController {
	return &AuthController{
		authService:   authService,
		userRepo:      userRepo,
		logger:        logger,
		tokenExpiry:   tokenExpiry,
		refreshExpiry: refreshExpiry,
	}
}

// Register godoc
// @Summary Register a new user
// @Description Registers a new user. The first user registered automatically gets the admin role.
// @Tags Auth
// @Accept json
// @Produce json
// @Param user body models.RegisterRequest true "User registration details"
// @Success 201 {object} models.SuccessResponse{data=models.TokenResponse} "Successfully registered and logged in"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 409 {object} models.ErrorResponse "Email already in use"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /auth/register [post]
func (ac *AuthController) Register(c *gin.Context) {
	var req models.RegisterRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate registration request
	validationResult := utils.NewValidationResult()

	if err := utils.ValidateEmail(req.Email, utils.ValidationOptions{
		MaxLength: 255,
		MinLength: 5,
		Required:  true,
	}); err != nil {
		validationResult.AddError("email", "INVALID_EMAIL", err.Error(), req.Email)
	}

	if err := utils.ValidatePassword(req.Password, utils.ValidationOptions{
		MaxLength:  72, // bcrypt max
		MinLength:  8,
		Required:   true,
		StrictMode: true,
	}); err != nil {
		validationResult.AddError("password", "INVALID_PASSWORD", err.Error(), "[REDACTED]")
	}

	if req.Name == "" {
		validationResult.AddError("name", "REQUIRED", "Name is required", "")
	} else if len(req.Name) > 100 {
		validationResult.AddError("name", "TOO_LONG", "Name cannot exceed 100 characters", req.Name)
	}

	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success: false,
			Error: models.ErrorInfo{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid registration request",
				Details: validationResult.GetErrors(),
			},
			Meta: models.MetadataResponse{
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
			},
		})
		return
	}

	// Create user model
	user := &models.User{
		Email:  req.Email,
		Name:   req.Name,
		Active: true,
		Roles: []models.UserRole{
			{
				Role: models.RoleUser, // Default role
			},
		},
	}

	// Check if this is the first user - make them admin
	_, count, err := ac.userRepo.List(c.Request.Context(), 0, 0) // Use List to get count
	if err != nil {
		ac.logger.WithError(err).Error("Failed to count users during registration")
		utils.InternalServerError(c, "Failed to check existing users")
		return
	}

	// First user gets admin role
	if count == 0 {
		user.Roles = append(user.Roles, models.UserRole{
			Role: models.RoleAdmin,
		})
	}

	// Hash the password
	hashedPassword, err := ac.authService.HashPassword(req.Password)
	if err != nil {
		ac.logger.WithError(err).Error("Failed to hash password during registration")
		utils.InternalServerError(c, "Failed to process registration")
		return
	}
	user.Password = hashedPassword

	// Generate tokens
	tokens, err := ac.authService.Register(c.Request.Context(), user)
	if err != nil {
		// Check for specific errors like email already exists
		// TODO: Replace string check with exported error variable from auth package if available
		if strings.Contains(err.Error(), "email address is already in use") {
			utils.Conflict(c, "Email address is already in use")
		} else {
			ac.logger.WithError(err).Error("Failed to register user")
			utils.InternalServerError(c, "Failed to register user")
		}
		return
	}

	// Return success response
	c.JSON(http.StatusCreated, models.SuccessResponse{
		Success: true,
		Data: models.TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(ac.tokenExpiry.Seconds()),
			ExpiresAt:    tokens.ExpiresAt,
			UserID:       user.ID,
			Roles:        user.GetRoleNames(),
		},
		Meta: models.MetadataResponse{
			Timestamp: time.Now(),
			RequestID: utils.GetRequestID(c),
		},
	})
}

// Login godoc
// @Summary Log in a user
// @Description Logs in a user with email and password, returning JWT tokens.
// @Tags Auth
// @Accept json
// @Produce json
// @Param credentials body models.LoginRequest true "User login credentials"
// @Success 200 {object} models.SuccessResponse{data=models.TokenResponse} "Successfully logged in"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Invalid credentials"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /auth/login [post]
func (ac *AuthController) Login(c *gin.Context) {
	var req models.LoginRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate login request
	validationResult := utils.NewValidationResult()

	// Explicitly set MaxLength for email validation
	if err := utils.ValidateEmail(req.Email, utils.ValidationOptions{Required: true, MaxLength: 255}); err != nil {
		validationResult.AddError("email", "INVALID_EMAIL", err.Error(), req.Email)
	}

	if req.Password == "" {
		validationResult.AddError("password", "REQUIRED", "Password is required", "[REDACTED]")
	}

	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success: false,
			Error: models.ErrorInfo{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid login request",
				Details: validationResult.GetErrors(),
			},
			Meta: models.MetadataResponse{
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
			},
		})
		return
	}

	// Authenticate user
	tokens, err := ac.authService.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		ac.logger.WithError(err).WithField("email", req.Email).Info("Failed login attempt")
		utils.Unauthorized(c, "Invalid email or password")
		return
	}

	// Get user from context (set by auth service)
	user, err := ac.userRepo.GetByEmail(c.Request.Context(), req.Email) // Renamed from FindByEmail
	if err != nil {
		ac.logger.WithError(err).Error("Failed to fetch user after successful login")
		utils.InternalServerError(c, "Failed to complete login")
		return
	}

	// Update last login time
	now := time.Now()
	user.LastLogin = &now
	if err := ac.userRepo.Update(c.Request.Context(), user); err != nil {
		// Non-critical error, just log it
		ac.logger.WithError(err).Error("Failed to update last login time")
	}

	// Return success response
	c.JSON(http.StatusOK, models.SuccessResponse{
		Success: true,
		Data: models.TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(ac.tokenExpiry.Seconds()),
			ExpiresAt:    tokens.ExpiresAt,
			UserID:       user.ID,
			Roles:        user.GetRoleNames(),
		},
		Meta: models.MetadataResponse{
			Timestamp: time.Now(),
			RequestID: utils.GetRequestID(c),
		},
	})
}

// Refresh godoc
// @Summary Refresh JWT tokens
// @Description Refreshes the access and refresh tokens using a valid refresh token.
// @Tags Auth
// @Accept json
// @Produce json
// @Param token body models.RefreshTokenRequest true "Refresh token details"
// @Success 200 {object} models.SuccessResponse{data=models.TokenResponse} "Successfully refreshed tokens"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Invalid or expired refresh token"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /auth/refresh [post]
func (ac *AuthController) Refresh(c *gin.Context) {
	var req models.RefreshTokenRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate refresh token
	if req.RefreshToken == "" {
		utils.BadRequest(c, "Refresh token is required")
		return
	}

	// Refresh token
	tokens, err := ac.authService.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		ac.logger.WithError(err).Info("Failed to refresh token")
		utils.Unauthorized(c, "Invalid or expired refresh token")
		return
	}

	// Get user ID from token details
	tokenDetails, err := ac.authService.Verify(context.Background(), tokens.AccessToken)
	if err != nil {
		ac.logger.WithError(err).Error("Failed to verify newly issued token")
		utils.InternalServerError(c, "Failed to complete token refresh")
		return
	}

	// Return success response
	c.JSON(http.StatusOK, models.SuccessResponse{
		Success: true,
		Data: models.TokenResponse{
			AccessToken:  tokens.AccessToken,
			RefreshToken: tokens.RefreshToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(ac.tokenExpiry.Seconds()),
			ExpiresAt:    tokens.ExpiresAt,
			UserID:       tokenDetails.UserID,
			Roles:        tokenDetails.Roles,
		},
		Meta: models.MetadataResponse{
			Timestamp: time.Now(),
			RequestID: utils.GetRequestID(c),
		},
	})
}

// Logout godoc
// @Summary Log out a user
// @Description Invalidates the current access token.
// @Tags Auth
// @Security BearerAuth
// @Success 204 "Successfully logged out"
// @Failure 400 {object} models.ErrorResponse "Invalid authorization header"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /auth/logout [post]
func (ac *AuthController) Logout(c *gin.Context) {
	// Get token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
		utils.BadRequest(c, "Invalid Authorization header")
		return
	}

	token := authHeader[7:]

	// Invalidate token
	err := ac.authService.Logout(c.Request.Context(), token)
	if err != nil {
		ac.logger.WithError(err).Error("Failed to logout")
		utils.InternalServerError(c, "Failed to complete logout")
		return
	}

	// Return success response
	c.Status(http.StatusNoContent)
}

// GetCurrentUser godoc
// @Summary Get current user details
// @Description Retrieves the details of the currently authenticated user.
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "Successfully retrieved user details"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /user/me [get]
func (ac *AuthController) GetCurrentUser(c *gin.Context) {
	// Get token details from context using the helper function
	tokenDetails, err := middleware.GetTokenDetails(c)
	if err != nil {
		utils.Unauthorized(c, fmt.Sprintf("Failed to get token details: %v", err))
		return
	}

	// Get user from database
	user, err := ac.userRepo.GetByID(c.Request.Context(), tokenDetails.UserID) // Use tokenDetails directly
	if err != nil {
		ac.logger.WithError(err).WithField("userID", tokenDetails.UserID).Error("Failed to fetch user") // Use tokenDetails.UserID
		utils.InternalServerError(c, "Failed to retrieve user information")
		return
	}

	// Return user response
	var lastLoginTime time.Time
	if user.LastLogin != nil {
		lastLoginTime = *user.LastLogin
	}
	// Wrap response in standard structure
	utils.SuccessResponse(c, models.UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		Roles:         user.GetRoleNames(),
		LastLogin:     lastLoginTime,
		EmailVerified: user.EmailVerified,
		Active:        user.Active,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

// UpdateCurrentUser godoc
// @Summary Update current user details
// @Description Updates the name and/or email of the currently authenticated user. Changing email requires re-verification.
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param user body object{name=string,email=string} true "User update details" example({"name": "Updated Name", "email": "updated.email@example.com"})
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "Successfully updated user details"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 409 {object} models.ErrorResponse "Email already in use"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /user/me [put]
func (ac *AuthController) UpdateCurrentUser(c *gin.Context) {
	// Get token details from context using the helper function
	tokenDetails, err := middleware.GetTokenDetails(c)
	if err != nil {
		utils.Unauthorized(c, fmt.Sprintf("Failed to get token details: %v", err))
		return
	}

	// Parse request body
	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}

	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate request
	validationResult := utils.NewValidationResult()

	if req.Name == "" {
		validationResult.AddError("name", "REQUIRED", "Name is required", "")
	} else if len(req.Name) > 100 {
		validationResult.AddError("name", "TOO_LONG", "Name cannot exceed 100 characters", req.Name)
	}

	if req.Email != "" {
		if err := utils.ValidateEmail(req.Email, utils.ValidationOptions{MaxLength: 255}); err != nil {
			validationResult.AddError("email", "INVALID_EMAIL", err.Error(), req.Email)
		}
	}

	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success: false,
			Error: models.ErrorInfo{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid update request",
				Details: validationResult.GetErrors(),
			},
			Meta: models.MetadataResponse{
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
			},
		})
		return
	}

	// Get user from database
	user, err := ac.userRepo.GetByID(c.Request.Context(), tokenDetails.UserID) // Use tokenDetails.UserID
	if err != nil {
		ac.logger.WithError(err).WithField("userID", tokenDetails.UserID).Error("Failed to fetch user for update") // Use tokenDetails.UserID
		utils.InternalServerError(c, "Failed to update user")
		return
	}

	// Check if email is being changed
	if req.Email != "" && req.Email != user.Email {
		// Check if email is already in use
		existingUser, err := ac.userRepo.GetByEmail(c.Request.Context(), req.Email) // Renamed from FindByEmail
		if err == nil && existingUser != nil && existingUser.ID != user.ID {
			utils.Conflict(c, "Email address is already in use")
			return
		}

		user.Email = req.Email
		user.EmailVerified = false // Require verification of new email
	}

	// Update user name
	if req.Name != "" {
		user.Name = req.Name
	}

	// Save changes
	if err := ac.userRepo.Update(c.Request.Context(), user); err != nil {
		ac.logger.WithError(err).WithField("userID", tokenDetails.UserID).Error("Failed to update user") // Use tokenDetails.UserID
		utils.InternalServerError(c, "Failed to update user")
		return
	}

	// Return updated user
	var lastLoginTime time.Time
	if user.LastLogin != nil {
		lastLoginTime = *user.LastLogin
	}
	// Wrap response in standard structure
	utils.SuccessResponse(c, models.UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		Roles:         user.GetRoleNames(),
		LastLogin:     lastLoginTime,
		EmailVerified: user.EmailVerified,
		Active:        user.Active,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

// UpdateUser godoc
// @Summary Update a user (Admin)
// @Description Updates a user's details by ID. Only admins can perform this action.
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID" example(1)
// @Param user body models.AdminUpdateUserRequest true "User update details (fields are optional)"
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "Successfully updated user"
// @Failure 400 {object} models.ErrorResponse "Invalid input or user ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Admin privileges required"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 409 {object} models.ErrorResponse "Email already in use"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/users/{id} [put]
func (ac *AuthController) UpdateUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID format")
		return
	}

	// Parse request body
	var req models.AdminUpdateUserRequest // Use the new model
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate request (similar to CreateUser, but password is optional)
	validationResult := utils.NewValidationResult()

	if req.Name != nil && *req.Name == "" { // Check if name is provided but empty
		validationResult.AddError("name", "REQUIRED", "Name cannot be empty if provided", "")
	} else if req.Name != nil && len(*req.Name) > 100 {
		validationResult.AddError("name", "TOO_LONG", "Name cannot exceed 100 characters", *req.Name)
	}

	if req.Email != nil && *req.Email != "" { // Check if email is provided and not empty
		if err := utils.ValidateEmail(*req.Email, utils.ValidationOptions{MaxLength: 255}); err != nil {
			validationResult.AddError("email", "INVALID_EMAIL", err.Error(), *req.Email)
		}
	}
	// TODO: Validate roles if provided in req.Roles (e.g., check against models.RoleUser, models.RoleAdmin)

	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success: false,
			Error: models.ErrorInfo{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid user data provided",
				Details: validationResult.GetErrors(),
			},
			Meta: models.MetadataResponse{
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
			},
		})
		return
	}

	// Get user from database
	user, err := ac.userRepo.GetByID(c.Request.Context(), uint(userID)) // Cast to uint
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.NotFound(c, "User not found")
		} else {
			ac.logger.WithError(err).WithField("userID", userID).Error("Failed to fetch user for update")
			utils.InternalServerError(c, "Failed to update user")
		}
		return
	}

	// Update fields if provided in the request
	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil && *req.Email != user.Email {
		// Check if email is already in use by another user
		existingUser, _ := ac.userRepo.GetByEmail(c.Request.Context(), *req.Email)
		if existingUser != nil && existingUser.ID != user.ID {
			utils.Conflict(c, "Email address is already in use")
			return
		}
		user.Email = *req.Email
		// Optionally force email verification on change?
		// user.EmailVerified = false
	}
	if req.Active != nil {
		user.Active = *req.Active
	}
	if req.EmailVerified != nil {
		user.EmailVerified = *req.EmailVerified
	}

	// Update roles if provided
	if req.Roles != nil {
		newRoles := []models.UserRole{}
		validRolesProvided := false
		for _, roleName := range *req.Roles {
			role := models.Role(roleName)
			if role == models.RoleUser || role == models.RoleAdmin {
				newRoles = append(newRoles, models.UserRole{Role: role})
				validRolesProvided = true
			} else {
				ac.logger.Warnf("Invalid role '%s' provided during user update", roleName)
			}
		}
		// Only update roles if at least one valid role was provided in the request
		if validRolesProvided {
			user.Roles = newRoles
		} else if len(*req.Roles) > 0 {
			// If roles were provided but none were valid, maybe return error?
			// For now, we just don't update roles if only invalid ones were given.
			ac.logger.Warnf("No valid roles provided in update request for user %d", userID)
		} else {
			// If an empty slice was explicitly provided, clear the roles
			user.Roles = []models.UserRole{}
		}
	}

	// Save changes
	if err := ac.userRepo.Update(c.Request.Context(), user); err != nil {
		ac.logger.WithError(err).WithField("userID", userID).Error("Failed to update user")
		utils.InternalServerError(c, "Failed to update user")
		return
	}

	// Return updated user
	var lastLoginTime time.Time
	if user.LastLogin != nil {
		lastLoginTime = *user.LastLogin
	}
	utils.SuccessResponse(c, models.UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		Roles:         user.GetRoleNames(),
		LastLogin:     lastLoginTime,
		EmailVerified: user.EmailVerified,
		Active:        user.Active,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

// DeleteUser godoc
// @Summary Delete a user (Admin)
// @Description Deletes a user by ID. Only admins can perform this action.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID" example(1)
// @Success 204 "Successfully deleted user"
// @Failure 400 {object} models.ErrorResponse "Invalid user ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Admin privileges required or cannot delete self"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/users/{id} [delete]
func (ac *AuthController) DeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID format")
		return
	}

	// Prevent admin from deleting themselves
	tokenDetails, _ := middleware.GetTokenDetails(c)
	if tokenDetails != nil && tokenDetails.UserID == uint(userID) {
		utils.Forbidden(c, "Cannot delete your own account")
		return
	}

	// Delete user
	err = ac.userRepo.Delete(c.Request.Context(), uint(userID)) // Cast to uint
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.NotFound(c, "User not found")
		} else {
			ac.logger.WithError(err).WithField("userID", userID).Error("Failed to delete user")
			utils.InternalServerError(c, "Failed to delete user")
		}
		return
	}

	// Return success response
	c.Status(http.StatusNoContent)
}

// CreateUser godoc
// @Summary Create a new user (Admin)
// @Description Creates a new user with specified details. Only admins can perform this action.
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param user body models.AdminCreateUserRequest true "New user details"
// @Success 201 {object} models.SuccessResponse{data=models.UserResponse} "Successfully created user"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Admin privileges required"
// @Failure 409 {object} models.ErrorResponse "Email already in use"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/users [post]
func (ac *AuthController) CreateUser(c *gin.Context) {
	var req models.AdminCreateUserRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate request
	validationResult := utils.NewValidationResult()

	if err := utils.ValidateEmail(req.Email, utils.ValidationOptions{Required: true, MaxLength: 255}); err != nil {
		validationResult.AddError("email", "INVALID_EMAIL", err.Error(), req.Email)
	}

	if err := utils.ValidatePassword(req.Password, utils.ValidationOptions{Required: true, MinLength: 8, MaxLength: 72}); err != nil {
		validationResult.AddError("password", "INVALID_PASSWORD", err.Error(), "[REDACTED]")
	}

	if req.Name == "" {
		validationResult.AddError("name", "REQUIRED", "Name is required", "")
	} else if len(req.Name) > 100 {
		validationResult.AddError("name", "TOO_LONG", "Name cannot exceed 100 characters", req.Name)
	}

	// Validate roles if provided
	validRoles := []models.UserRole{}
	if len(req.Roles) > 0 {
		hasUserRole := false
		for _, roleName := range req.Roles {
			role := models.Role(roleName)
			if role == models.RoleUser || role == models.RoleAdmin {
				validRoles = append(validRoles, models.UserRole{Role: role})
				if role == models.RoleUser {
					hasUserRole = true
				}
			} else {
				validationResult.AddError("roles", "INVALID_ROLE", fmt.Sprintf("Invalid role specified: %s", roleName), roleName)
			}
		}
		// Ensure 'user' role is always present if other roles are specified
		if !hasUserRole && len(validRoles) > 0 {
			validRoles = append(validRoles, models.UserRole{Role: models.RoleUser})
		}
	} else {
		// Default to 'user' role if none provided
		validRoles = append(validRoles, models.UserRole{Role: models.RoleUser})
	}

	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success: false,
			Error: models.ErrorInfo{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid user data provided",
				Details: validationResult.GetErrors(),
			},
			Meta: models.MetadataResponse{
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
			},
		})
		return
	}

	// Check if email already exists
	existingUser, _ := ac.userRepo.GetByEmail(c.Request.Context(), req.Email)
	if existingUser != nil {
		utils.Conflict(c, "Email address is already in use")
		return
	}

	// Hash the password
	hashedPassword, err := ac.authService.HashPassword(req.Password)
	if err != nil {
		ac.logger.WithError(err).Error("Failed to hash password during admin user creation")
		utils.InternalServerError(c, "Failed to create user")
		return
	}

	// Create user model
	user := &models.User{
		Email:         req.Email,
		Password:      hashedPassword,
		Name:          req.Name,
		Roles:         validRoles,
		Active:        req.Active,        // Defaults to false if omitted in JSON
		EmailVerified: req.EmailVerified, // Defaults to false if omitted
	}
	// Explicitly set default for Active if not provided
	// Corrected boolean logic: check if ContentLength is 0 OR content type is not JSON
	if c.Request.ContentLength == 0 || !strings.Contains(c.ContentType(), "application/json") {
		// If no body or not JSON, assume defaults
		user.Active = true
	} else {
		// Check if 'active' field was present in the JSON
		var raw map[string]interface{}
		_ = c.ShouldBindJSON(&raw) // Re-bind to check presence, ignore error
		if _, ok := raw["active"]; !ok {
			user.Active = true // Default to true if key is missing
		}
	}

	// Create user in database
	if err := ac.userRepo.Create(c.Request.Context(), user); err != nil {
		ac.logger.WithError(err).Error("Failed to create user in database")
		utils.InternalServerError(c, "Failed to create user")
		return
	}

	// Return created user
	var lastLoginTime time.Time // Will be zero time
	c.JSON(http.StatusCreated, models.SuccessResponse{
		Success: true,
		Data: models.UserResponse{
			ID:            user.ID,
			Email:         user.Email,
			Name:          user.Name,
			Roles:         user.GetRoleNames(),
			LastLogin:     lastLoginTime,
			EmailVerified: user.EmailVerified,
			Active:        user.Active,
			CreatedAt:     user.CreatedAt,
			UpdatedAt:     user.UpdatedAt,
		},
		Meta: models.MetadataResponse{
			Timestamp: time.Now(),
			RequestID: utils.GetRequestID(c),
		},
	})
}

// GetUserByID godoc
// @Summary Get user by ID (Admin)
// @Description Retrieves details for a specific user by their ID. Only admins can perform this action.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID" example(1)
// @Success 200 {object} models.SuccessResponse{data=models.UserResponse} "Successfully retrieved user details"
// @Failure 400 {object} models.ErrorResponse "Invalid user ID"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Admin privileges required"
// @Failure 404 {object} models.ErrorResponse "User not found"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/users/{id} [get]
func (ac *AuthController) GetUserByID(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	if err != nil {
		utils.BadRequest(c, "Invalid user ID format")
		return
	}

	// Get user from database
	user, err := ac.userRepo.GetByID(c.Request.Context(), uint(userID)) // Cast to uint
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.NotFound(c, "User not found")
		} else {
			ac.logger.WithError(err).WithField("userID", userID).Error("Failed to fetch user by ID")
			utils.InternalServerError(c, "Failed to retrieve user information")
		}
		return
	}

	// Return user response
	var lastLoginTime time.Time
	if user.LastLogin != nil {
		lastLoginTime = *user.LastLogin
	}
	utils.SuccessResponse(c, models.UserResponse{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		Roles:         user.GetRoleNames(),
		LastLogin:     lastLoginTime,
		EmailVerified: user.EmailVerified,
		Active:        user.Active,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	})
}

// ListUsers godoc
// @Summary List all users (Admin)
// @Description Retrieves a paginated list of all users. Only admins can perform this action.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Number of items per page" default(10) minimum(1) maximum(100)
// @Param sort_by query string false "Field to sort by (e.g., email, name, created_at)" default(id)
// @Param sort_order query string false "Sort order (asc, desc)" default(asc) Enums(asc, desc)
// @Param search query string false "Search term for email or name"
// @Param active query bool false "Filter by active status"
// @Success 200 {object} models.SuccessResponse{data=models.UserListResponse} "Successfully retrieved users" // Use UserListResponse
// @Failure 400 {object} models.ErrorResponse "Invalid query parameters"
// @Failure 401 {object} models.ErrorResponse "Authentication required"
// @Failure 403 {object} models.ErrorResponse "Admin privileges required"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /admin/users [get]
func (ac *AuthController) ListUsers(c *gin.Context) {
	// Pagination
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		pageSize = 100
	} // Max page size limit
	offset := (page - 1) * pageSize

	// Sorting (Add validation for allowed sort fields if needed)
	// sortBy := c.DefaultQuery("sort_by", "id") // Removed unused variable
	sortOrder := c.DefaultQuery("sort_order", "asc")
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "asc"
	}
	_ = sortOrder // Avoid unused variable error until sorting is implemented

	// Filtering
	// search := c.Query("search") // Removed unused variable
	// activeFilter := c.Query("active") // Removed unused variable

	// Get users from repository - Corrected call signature
	users, totalCount, err := ac.userRepo.List(c.Request.Context(), offset, pageSize) // Removed extra args
	if err != nil {
		ac.logger.WithError(err).Error("Failed to list users")
		utils.InternalServerError(c, "Failed to retrieve users")
		return
	}

	// TODO: Implement filtering (search, activeFilter) and sorting (sortBy, sortOrder) in Go after fetching all users
	// This is less efficient but necessary if the repository doesn't support these directly.

	// Convert users to response model
	userResponses := make([]models.UserResponse, len(users))
	for i, user := range users {
		var lastLoginTime time.Time
		if user.LastLogin != nil {
			lastLoginTime = *user.LastLogin
		}
		userResponses[i] = models.UserResponse{
			ID:            user.ID,
			Email:         user.Email,
			Name:          user.Name,
			Roles:         user.GetRoleNames(),
			LastLogin:     lastLoginTime,
			EmailVerified: user.EmailVerified,
			Active:        user.Active,
			CreatedAt:     user.CreatedAt,
			UpdatedAt:     user.UpdatedAt,
		}
	}

	// Return paginated response using standard Gin JSON
	c.JSON(http.StatusOK, models.SuccessResponse{ // Use SuccessResponse
		Success: true,
		Data: models.UserListResponse{ // Embed UserListResponse in Data
			Users: userResponses,
			Metadata: models.MetadataResponse{ // Embed metadata within UserListResponse
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
				Pagination: &models.PaginationResponse{
					Page:       page,
					PageSize:   pageSize,
					TotalItems: int(totalCount), // Use totalCount from repo
					TotalPages: (int(totalCount) + pageSize - 1) / pageSize,
				},
			},
		},
		Meta: models.MetadataResponse{ // Keep top-level meta as well for consistency
			Timestamp: time.Now(),
			RequestID: utils.GetRequestID(c),
			Pagination: &models.PaginationResponse{
				Page:       page,
				PageSize:   pageSize,
				TotalItems: int(totalCount),
				TotalPages: (int(totalCount) + pageSize - 1) / pageSize,
			},
		},
	})
}

// ChangePassword godoc
// @Summary Change current user password
// @Description Allows the authenticated user to change their own password.
// @Tags User
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param passwords body models.ChangePasswordRequest true "Password change details"
// @Success 204 "Password successfully changed"
// @Failure 400 {object} models.ErrorResponse "Invalid input"
// @Failure 401 {object} models.ErrorResponse "Authentication required or incorrect current password"
// @Failure 500 {object} models.ErrorResponse "Internal server error"
// @Router /user/password [put]
func (ac *AuthController) ChangePassword(c *gin.Context) {
	// Get token details from context
	tokenDetails, err := middleware.GetTokenDetails(c)
	if err != nil {
		utils.Unauthorized(c, fmt.Sprintf("Failed to get token details: %v", err))
		return
	}

	// Parse request body
	var req models.ChangePasswordRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	// Validate new password
	validationResult := utils.NewValidationResult()
	if err := utils.ValidatePassword(req.NewPassword, utils.ValidationOptions{
		Required:   true,
		MinLength:  8,
		MaxLength:  72, // bcrypt max
		StrictMode: true,
	}); err != nil {
		validationResult.AddError("new_password", "INVALID_PASSWORD", err.Error(), "[REDACTED]")
	}
	if req.CurrentPassword == "" {
		validationResult.AddError("current_password", "REQUIRED", "Current password is required", "[REDACTED]")
	}

	if !validationResult.IsValid() {
		// Use standard Gin JSON response for validation errors
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success: false,
			Error: models.ErrorInfo{
				Code:    "VALIDATION_ERROR",
				Message: "Invalid password change request",
				Details: validationResult.GetErrors(),
			},
			Meta: models.MetadataResponse{
				Timestamp: time.Now(),
				RequestID: utils.GetRequestID(c),
			},
		})
		return
	}

	// Change password using auth service
	// TODO: Add ChangePassword method to auth.Service interface and implementation
	// err = ac.authService.ChangePassword(c.Request.Context(), tokenDetails.UserID, req.CurrentPassword, req.NewPassword)
	err = errors.New("ChangePassword method not implemented in auth service") // Placeholder error
	if err != nil {
		// TODO: Replace string check with exported error variable if available
		if errors.Is(err, auth.ErrInvalidCredentials) || strings.Contains(err.Error(), "Incorrect current password") {
			utils.Unauthorized(c, "Incorrect current password")
		} else if strings.Contains(err.Error(), "not implemented") { // Handle placeholder error
			ac.logger.Error("ChangePassword service method not implemented")
			utils.InternalServerError(c, "Feature not implemented")
		} else {
			ac.logger.WithError(err).WithField("userID", tokenDetails.UserID).Error("Failed to change password")
			utils.InternalServerError(c, "Failed to change password")
		}
		return
	}

	// Return success response
	c.Status(http.StatusNoContent)
}
