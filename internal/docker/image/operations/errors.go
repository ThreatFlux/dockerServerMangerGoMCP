package operations

import "errors"

// Common errors for image operations
var (
	// ErrImageNotFound indicates the image was not found
	ErrImageNotFound = errors.New("image not found")

	// ErrInvalidImageID indicates an invalid image ID was provided
	ErrInvalidImageID = errors.New("invalid image ID or name")

	// ErrContextCancelled indicates the context was cancelled during the operation
	ErrContextCancelled = errors.New("operation cancelled by context")

	// ErrImageTag indicates an error occurred during image tagging
	ErrImageTag = errors.New("failed to tag image")

	// ErrInvalidTagReference indicates an invalid tag reference was provided
	ErrInvalidTagReference = errors.New("invalid tag reference")

	// ErrImageInUse indicates the image is in use by a container
	ErrImageInUse = errors.New("image is in use by a container")

	// ErrImageNotFoundDuringRemoval indicates the image was not found during removal
	ErrImageNotFoundDuringRemoval = errors.New("image not found during removal")

	// ErrImageRemove indicates an error occurred during image removal
	ErrImageRemove = errors.New("failed to remove image")

	// ErrImagePrune indicates an error occurred during image pruning
	ErrImagePrune = errors.New("failed to prune images")

	// ErrImageBuild indicates an error occurred during image build
	ErrImageBuild = errors.New("failed to build image")

	// ErrImagePush indicates an error occurred during image push
	ErrImagePush = errors.New("failed to push image")

	// ErrImagePull indicates an error occurred during image pull
	ErrImagePull = errors.New("failed to pull image")

	// ErrLoadImage indicates an error occurred while loading an image tarball
	ErrLoadImage = errors.New("failed to load image")

	// ErrSaveImage indicates an error occurred while saving an image tarball
	ErrSaveImage = errors.New("failed to save image")

	// ErrInvalidBuildContext indicates an invalid build context was provided (Generic)
	ErrInvalidBuildContext = errors.New("invalid build context")

	// ErrBuildContextNotFound indicates the build context path was not found
	ErrBuildContextNotFound = errors.New("build context not found")

	// ErrBuildContextCreation indicates an error creating the build context tarball
	ErrBuildContextCreation = errors.New("failed to create build context")

	// ErrBuildTimeout indicates the build operation timed out
	ErrBuildTimeout = errors.New("build operation timed out")

	// ErrBuildCancelled indicates the build operation was cancelled
	ErrBuildCancelled = errors.New("build operation cancelled")

	// ErrInvalidBuildOptions indicates invalid build options were provided
	ErrInvalidBuildOptions = errors.New("invalid build options")

	// ErrDockerfileNotFound indicates the Dockerfile was not found
	ErrDockerfileNotFound = errors.New("Dockerfile not found")

	// ErrInvalidImageReference indicates an invalid image reference was provided
	ErrInvalidImageReference = errors.New("invalid image reference")

	// ErrRegistryAuth indicates an authentication error with the registry
	ErrRegistryAuth = errors.New("registry authentication error")

	// ErrPullTimeout indicates the pull operation timed out
	ErrPullTimeout = errors.New("pull operation timed out")

	// ErrPullCancelled indicates the pull operation was cancelled
	ErrPullCancelled = errors.New("pull operation cancelled")
)
