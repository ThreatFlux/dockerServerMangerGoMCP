package utils

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestContext() (*httptest.ResponseRecorder, *gin.Context) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	return w, c
}

func TestErrorResponse(t *testing.T) {
	w, c := setupTestContext()

	// Call the function
	ErrorResponse(c, http.StatusBadRequest, "TEST_ERROR", "Test error message", "Error details")

	// Check the response
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Parse the response body
	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check the response content
	assert.False(t, response.Success)
	require.NotNil(t, response.Error)
	assert.Equal(t, "TEST_ERROR", response.Error.Code)
	assert.Equal(t, "Test error message", response.Error.Message)
	assert.Equal(t, "Error details", response.Error.Details)
	require.NotNil(t, response.Meta)
	assert.NotZero(t, response.Meta.Timestamp)
}

func TestSuccessResponse(t *testing.T) {
	w, c := setupTestContext()

	// Test data
	testData := map[string]string{
		"key": "value",
	}

	// Call the function
	SuccessResponse(c, testData)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check the response content
	assert.True(t, response.Success)
	assert.Nil(t, response.Error)
	require.NotNil(t, response.Data)
	require.NotNil(t, response.Meta)
	assert.NotZero(t, response.Meta.Timestamp)

	// Check the data
	dataJSON, err := json.Marshal(response.Data)
	require.NoError(t, err)
	var data map[string]string
	err = json.Unmarshal(dataJSON, &data)
	require.NoError(t, err)
	assert.Equal(t, "value", data["key"])
}

func TestPaginatedResponse(t *testing.T) {
	w, c := setupTestContext()

	// Test data
	testData := []string{"item1", "item2"}

	// Call the function
	PaginatedResponse(c, testData, 2, 10, 25)

	// Check the response
	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response body
	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check the response content
	assert.True(t, response.Success)
	assert.Nil(t, response.Error)
	require.NotNil(t, response.Data)
	require.NotNil(t, response.Meta)
	assert.Equal(t, 2, response.Meta.Page)
	assert.Equal(t, 10, response.Meta.PerPage)
	assert.Equal(t, 3, response.Meta.TotalPages)
	assert.Equal(t, 25, response.Meta.Total)
	assert.NotZero(t, response.Meta.Timestamp)
}

func TestStandardErrorResponses(t *testing.T) {
	tests := []struct {
		name           string
		function       func(*gin.Context, string)
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "BadRequest",
			function:       BadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "BAD_REQUEST",
		},
		{
			name:           "Unauthorized",
			function:       Unauthorized,
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "UNAUTHORIZED",
		},
		{
			name:           "Forbidden",
			function:       Forbidden,
			expectedStatus: http.StatusForbidden,
			expectedCode:   "FORBIDDEN",
		},
		{
			name:           "NotFound",
			function:       NotFound,
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NOT_FOUND",
		},
		{
			name:           "InternalServerError",
			function:       InternalServerError,
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "INTERNAL_SERVER_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, c := setupTestContext()

			// Call the function
			tt.function(c, "Test message")

			// Check the response
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse the response body
			var response Response
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			// Check the response content
			assert.False(t, response.Success)
			require.NotNil(t, response.Error)
			assert.Equal(t, tt.expectedCode, response.Error.Code)
			assert.Equal(t, "Test message", response.Error.Message)
		})
	}
}

func TestBindJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestStruct struct {
		Name string `json:"name" binding:"required"`
		Age  int    `json:"age" binding:"required"`
	}

	// Test valid JSON
	t.Run("valid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Create a valid request with JSON body
		jsonData := `{"name":"John","age":30}`
		c.Request = httptest.NewRequest("POST", "/", StringToReadCloser(jsonData))
		c.Request.Header.Set("Content-Type", "application/json")

		// Bind the JSON
		var obj TestStruct
		result := BindJSON(c, &obj)

		// Check the result
		assert.True(t, result)
		assert.Equal(t, "John", obj.Name)
		assert.Equal(t, 30, obj.Age)
	})

	// Test invalid JSON
	t.Run("invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Create an invalid request with JSON body
		jsonData := `{"name":"John"}` // Missing required age field
		c.Request = httptest.NewRequest("POST", "/", StringToReadCloser(jsonData))
		c.Request.Header.Set("Content-Type", "application/json")

		// Bind the JSON
		var obj TestStruct
		result := BindJSON(c, &obj)

		// Check the result
		assert.False(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestBindQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestQuery struct {
		Name string `form:"name" binding:"required"`
		Age  int    `form:"age" binding:"required"`
	}

	// Test valid query
	t.Run("valid query", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Create a valid request with query parameters
		c.Request = httptest.NewRequest("GET", "/?name=John&age=30", nil)

		// Bind the query
		var obj TestQuery
		result := BindQuery(c, &obj)

		// Check the result
		assert.True(t, result)
		assert.Equal(t, "John", obj.Name)
		assert.Equal(t, 30, obj.Age)
	})

	// Test invalid query
	t.Run("invalid query", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		// Create an invalid request with query parameters
		c.Request = httptest.NewRequest("GET", "/?name=John", nil) // Missing required age parameter

		// Bind the query
		var obj TestQuery
		result := BindQuery(c, &obj)

		// Check the result
		assert.False(t, result)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// StringToReadCloser converts a string to an io.ReadCloser
func StringToReadCloser(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}

func TestJSONConversion(t *testing.T) {
	// Test data
	type TestStruct struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}
	testObj := TestStruct{
		Name: "John",
		Age:  30,
	}

	// Test ToJSON
	t.Run("ToJSON", func(t *testing.T) {
		data, err := ToJSON(testObj)
		require.NoError(t, err)
		assert.JSONEq(t, `{"name":"John","age":30}`, string(data))
	})

	// Test FromJSON
	t.Run("FromJSON", func(t *testing.T) {
		jsonData := []byte(`{"name":"Alice","age":25}`)
		var obj TestStruct
		err := FromJSON(jsonData, &obj)
		require.NoError(t, err)
		assert.Equal(t, "Alice", obj.Name)
		assert.Equal(t, 25, obj.Age)
	})
}
