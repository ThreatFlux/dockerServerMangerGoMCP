package status

import (
	"github.com/threatflux/dockerServerMangerGoMCP/internal/models"
)

// StatusTracker defines the interface for tracking deployment status,
// specifically the methods needed by the ComposeService.
// Note: This interface might be redundant if interfaces.ComposeStatusTracker is used consistently.
type StatusTracker interface {
	GetDeployment(projectName string) (*models.DeploymentInfo, bool) // Use models.DeploymentInfo
}
