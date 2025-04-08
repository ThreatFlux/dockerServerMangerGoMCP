#!/bin/bash

# Basic API Test Script for Docker Server Manager

set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Uncomment for debugging - prints each command before execution

BASE_URL="http://localhost:8080/api/v1"
ADMIN_EMAIL="admin@example.com"
ADMIN_PASS="StrongPass!1" # Use a secure password in real scenarios
ADMIN_NAME="Admin User"
CONTAINER_NAME="dsm_postgres_dev" # The dev DB container

echo "--- Ensuring Server and DB are Running ---"
# Check if server is responding, start if not (simple check)
if ! curl -s --head "$BASE_URL/health" | head -n 1 | grep "200 OK" > /dev/null; then
  echo "Server not responding. Attempting to start DB and Server..."
  make dev-db-up || { echo "Failed to start DB"; exit 1; }
  make dev-start || { echo "Failed to start server"; exit 1; }
  echo "Waiting for server to initialize..."
  sleep 5 # Wait a bit longer after starting
  # Verify health again
  if ! curl -s --head "$BASE_URL/health" | head -n 1 | grep "200 OK" > /dev/null; then
    echo "Server failed to start or respond after 'make dev-start'."
    exit 1
  fi
else
  echo "Server already running."
fi

echo -e "\n--- Registering Admin User (ignore error if exists) ---"
curl -s -X POST "$BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$ADMIN_EMAIL"'",
    "password": "'"$ADMIN_PASS"'",
    "name": "'"$ADMIN_NAME"'"
  }' || echo "Registration endpoint failed or user already exists (expected)."
echo "" # Newline

echo -e "\n--- Logging In ---"
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "'"$ADMIN_EMAIL"'",
    "password": "'"$ADMIN_PASS"'"
  }')

echo "Login Response JSON: $LOGIN_RESPONSE"

# Extract token using jq (adjust path for SuccessResponse structure)
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.access_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
  echo "Login failed or token not found in response."
  exit 1
fi

echo "Login successful. Token obtained."
# echo "Access Token: $ACCESS_TOKEN" # Uncomment to display token

echo -e "\n--- Getting Container ID ---"
CONTAINER_ID=$(docker ps --filter "name=$CONTAINER_NAME" --format "{{.ID}}" | head -n 1)

if [ -z "$CONTAINER_ID" ]; then
  echo "Failed to find running container named '$CONTAINER_NAME'."
  echo "Make sure the dev database is running ('make dev-db-up')."
  exit 1
fi

echo "Found container ID: $CONTAINER_ID"

echo -e "\n--- Testing GET /containers/:id ---"
# Get status code separately
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/containers/$CONTAINER_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

# Get body separately
HTTP_BODY=$(curl -s -X GET "$BASE_URL/containers/$CONTAINER_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")


echo "Response Status Code: $HTTP_STATUS"
echo "Response Body:"
echo "$HTTP_BODY" | jq . # Pretty print JSON if possible

if [ "$HTTP_STATUS" -eq 200 ]; then
  echo -e "\n--- SUCCESS: Successfully retrieved container info. ---"
else
  echo -e "\n--- FAILED: Did not get 200 OK for container info. ---"
  exit 1
fi

echo -e "\n--- Testing GET /containers ---"
# Get status code separately
HTTP_STATUS_LIST=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/containers?page=1&page_size=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

# Get body separately
HTTP_BODY_LIST=$(curl -s -X GET "$BASE_URL/containers?page=1&page_size=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Response Status Code: $HTTP_STATUS_LIST"
echo "Response Body:"
echo "$HTTP_BODY_LIST" | jq . # Pretty print JSON if possible

if [ "$HTTP_STATUS_LIST" -eq 200 ]; then
  echo -e "\n--- SUCCESS: Successfully listed containers. ---"
else
  echo -e "\n--- FAILED: Did not get 200 OK for listing containers. ---"
  exit 1
fi

echo -e "\n--- Pre-cleaning test container (if exists) ---"
# Attempt to stop and remove the container, ignore errors if it doesn't exist
curl -s -X POST "$BASE_URL/containers/test-alpine-container/stop" -H "Authorization: Bearer $ACCESS_TOKEN" || true
sleep 1
curl -s -X DELETE "$BASE_URL/containers/test-alpine-container?force=true" -H "Authorization: Bearer $ACCESS_TOKEN" || true
sleep 1

echo -e "\n--- Testing POST /containers (Create alpine) ---"
CREATE_PAYLOAD='{
  "name": "test-alpine-container",
  "image": "alpine:latest",
  "command": ["sleep", "3600"]
}'

# Get status code separately
HTTP_STATUS_CREATE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$CREATE_PAYLOAD")

# Get body separately
HTTP_BODY_CREATE=$(curl -s -X POST "$BASE_URL/containers" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$CREATE_PAYLOAD")

echo "Response Status Code: $HTTP_STATUS_CREATE"

if [ "$HTTP_STATUS_CREATE" -eq 201 ]; then # Expect 201 Created
  # Get body only on success
  HTTP_BODY_CREATE=$(curl -s -X POST "$BASE_URL/containers" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$CREATE_PAYLOAD") # This will fail due to name conflict, need to get body from first call or inspect

  # Let's inspect instead to get the ID reliably after creation
  echo "Inspecting created container..."
  INSPECT_BODY=$(curl -s -X GET "$BASE_URL/containers/test-alpine-container" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Inspect Response Body:"
  echo "$INSPECT_BODY" | jq .

  NEW_CONTAINER_ID=$(echo "$INSPECT_BODY" | jq -r '.data.container_id')

  if [ -z "$NEW_CONTAINER_ID" ] || [ "$NEW_CONTAINER_ID" == "null" ]; then
      echo -e "\n--- WARNING: Created container but failed to retrieve its ID via inspect. ---"
      # Attempt to get ID by listing and filtering name (less reliable)
      LIST_BODY=$(curl -s -X GET "$BASE_URL/containers?page=1&page_size=100" -H "Authorization: Bearer $ACCESS_TOKEN")
      NEW_CONTAINER_ID=$(echo "$LIST_BODY" | jq -r '.data.containers[] | select(.name=="test-alpine-container") | .container_id')
      if [ -z "$NEW_CONTAINER_ID" ] || [ "$NEW_CONTAINER_ID" == "null" ]; then
          echo -e "\n--- FAILED: Could not determine ID of created container. ---"
          exit 1
      else
           echo "Found Container ID via list: $NEW_CONTAINER_ID"
      fi
  else
       echo "Found Container ID via inspect: $NEW_CONTAINER_ID"
  fi

  echo -e "\n--- SUCCESS: Successfully created container (Status Code 201). ---"

else
  # Get body on failure to show error
  HTTP_BODY_CREATE=$(curl -s -X POST "$BASE_URL/containers" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$CREATE_PAYLOAD")
  echo "Response Body (Error):"
  echo "$HTTP_BODY_CREATE" | jq .
  echo -e "\n--- FAILED: Did not get 201 Created for creating container. ---"
  exit 1
fi

echo -e "\n--- Testing POST /containers/:id/start ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  HTTP_STATUS_START=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/start" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_START"

  if [ "$HTTP_STATUS_START" -eq 204 ]; then # Expect 204 No Content on success
    echo -e "\n--- SUCCESS: Successfully started container $NEW_CONTAINER_ID. ---"
    # Verify status by inspecting again
    sleep 2 # Give container a moment to fully start
    INSPECT_BODY_AFTER_START=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    CONTAINER_STATUS=$(echo "$INSPECT_BODY_AFTER_START" | jq -r '.data.status')
    echo "Container status after start: $CONTAINER_STATUS"
    if [[ "$CONTAINER_STATUS" != "running" ]]; then
       echo -e "\n--- FAILED: Container status is not 'running' after start command. ---"
       exit 1
    fi
  else
    echo -e "\n--- FAILED: Did not get 204 No Content for starting container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping start test as NEW_CONTAINER_ID was not set."
fi

# Add a small delay to ensure the container has time to produce some output if needed
sleep 1

echo -e "\n--- Testing GET /containers/:id/logs ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  HTTP_STATUS_LOGS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/logs?stdout=true&stderr=true&tail=10" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_LOGS"

  if [ "$HTTP_STATUS_LOGS" -eq 200 ]; then # Expect 200 OK for logs
    echo -e "\n--- SUCCESS: Successfully retrieved logs status for container $NEW_CONTAINER_ID. ---"
    # We don't check content here, just that the endpoint works
    # Actual log content might be empty for a simple 'sleep' container initially
    LOG_BODY=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/logs?stdout=true&stderr=true&tail=10" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    echo "Log Body (last 10 lines):"
    echo "$LOG_BODY"
  else
    echo -e "\n--- FAILED: Did not get 200 OK for getting logs. ---"
    exit 1
  fi
else
   echo "WARN: Skipping logs test as NEW_CONTAINER_ID was not set."
fi


echo -e "\n--- Testing POST /containers/:id/stop ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Stop with default timeout
  HTTP_STATUS_STOP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/stop" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_STOP"

  if [ "$HTTP_STATUS_STOP" -eq 204 ]; then # Expect 204 No Content on success
    echo -e "\n--- SUCCESS: Successfully stopped container $NEW_CONTAINER_ID. ---"
    # Verify status by inspecting again
    sleep 1 # Give container a moment to fully stop
    INSPECT_BODY_AFTER_STOP=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    CONTAINER_STATUS_STOP=$(echo "$INSPECT_BODY_AFTER_STOP" | jq -r '.data.status')
    echo "Container status after stop: $CONTAINER_STATUS_STOP"
    # Status might be 'exited' or similar, check for not 'running'
    if [[ "$CONTAINER_STATUS_STOP" == "running" ]]; then
       echo -e "\n--- FAILED: Container status is still 'running' after stop command. ---"
       exit 1
    fi
  else
    echo -e "\n--- FAILED: Did not get 204 No Content for stopping container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping stop test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing POST /containers/:id/restart ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Restart with default timeout
  HTTP_STATUS_RESTART=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/restart" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_RESTART"

  if [ "$HTTP_STATUS_RESTART" -eq 204 ]; then # Expect 204 No Content on success
    echo -e "\n--- SUCCESS: Successfully restarted container $NEW_CONTAINER_ID. ---"
    # Verify status by inspecting again
    sleep 2 # Give container a moment to fully restart
    INSPECT_BODY_AFTER_RESTART=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    CONTAINER_STATUS_RESTART=$(echo "$INSPECT_BODY_AFTER_RESTART" | jq -r '.data.status')
    echo "Container status after restart: $CONTAINER_STATUS_RESTART"
    if [[ "$CONTAINER_STATUS_RESTART" != "running" ]]; then
       echo -e "\n--- FAILED: Container status is not 'running' after restart command. ---"
       exit 1
    fi
  else
    echo -e "\n--- FAILED: Did not get 204 No Content for restarting container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping restart test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing POST /containers/:id/pause ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  HTTP_STATUS_PAUSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/pause" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_PAUSE"

  if [ "$HTTP_STATUS_PAUSE" -eq 204 ]; then # Expect 204 No Content on success
    echo -e "\n--- SUCCESS: Successfully paused container $NEW_CONTAINER_ID. ---"
    # Verify status by inspecting again
    sleep 1 # Give container a moment to update status
    INSPECT_BODY_AFTER_PAUSE=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    CONTAINER_STATUS_PAUSE=$(echo "$INSPECT_BODY_AFTER_PAUSE" | jq -r '.data.status')
    echo "Container status after pause: $CONTAINER_STATUS_PAUSE"
    if [[ "$CONTAINER_STATUS_PAUSE" != "paused" ]]; then
       echo -e "\n--- FAILED: Container status is not 'paused' after pause command. ---"
       exit 1
    fi
  else
    echo -e "\n--- FAILED: Did not get 204 No Content for pausing container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping pause test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing POST /containers/:id/unpause ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  HTTP_STATUS_UNPAUSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/unpause" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_UNPAUSE"

  if [ "$HTTP_STATUS_UNPAUSE" -eq 204 ]; then # Expect 204 No Content on success
    echo -e "\n--- SUCCESS: Successfully unpaused container $NEW_CONTAINER_ID. ---"
    # Verify status by inspecting again
    sleep 1 # Give container a moment to update status
    INSPECT_BODY_AFTER_UNPAUSE=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    CONTAINER_STATUS_UNPAUSE=$(echo "$INSPECT_BODY_AFTER_UNPAUSE" | jq -r '.data.status')
    echo "Container status after unpause: $CONTAINER_STATUS_UNPAUSE"
    if [[ "$CONTAINER_STATUS_UNPAUSE" != "running" ]]; then
       echo -e "\n--- FAILED: Container status is not 'running' after unpause command. ---"
       exit 1
    fi
  else
    echo -e "\n--- FAILED: Did not get 204 No Content for unpausing container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping unpause test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing POST /containers/:id/rename ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  NEW_NAME="test-alpine-renamed-$$" # Add random element to avoid conflicts
  RENAME_PAYLOAD='{"name": "'"$NEW_NAME"'"}'

  HTTP_STATUS_RENAME=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/rename" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$RENAME_PAYLOAD")

  echo "Response Status Code: $HTTP_STATUS_RENAME"

  if [ "$HTTP_STATUS_RENAME" -eq 200 ]; then # Expect 200 OK on success
    echo -e "\n--- SUCCESS: Successfully renamed container $NEW_CONTAINER_ID to $NEW_NAME. ---"
    # Verify name by inspecting again (using the new name)
    sleep 1
    INSPECT_BODY_AFTER_RENAME=$(curl -s -X GET "$BASE_URL/containers/$NEW_NAME" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    CONTAINER_NAME_RENAME=$(echo "$INSPECT_BODY_AFTER_RENAME" | jq -r '.data.name')
    echo "Container name after rename: $CONTAINER_NAME_RENAME"
    if [[ "$CONTAINER_NAME_RENAME" != "$NEW_NAME" ]]; then
       echo -e "\n--- FAILED: Container name is not '$NEW_NAME' after rename command. ---"
       exit 1
    fi
    # Update NEW_CONTAINER_ID to the new name/ID for cleanup
    NEW_CONTAINER_ID=$(echo "$INSPECT_BODY_AFTER_RENAME" | jq -r '.data.container_id')
  else
    # Get body on failure
    HTTP_BODY_RENAME=$(curl -s -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/rename" \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$RENAME_PAYLOAD")
    echo "Response Body (Error):"
    echo "$HTTP_BODY_RENAME" | jq .
    echo -e "\n--- FAILED: Did not get 200 OK for renaming container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping rename test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing GET /containers/:id/stats ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Get stats (one-shot)
  HTTP_STATUS_STATS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/stats" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_STATS"

  if [ "$HTTP_STATUS_STATS" -eq 200 ]; then # Expect 200 OK
    echo -e "\n--- SUCCESS: Successfully retrieved stats for container $NEW_CONTAINER_ID. ---"
    HTTP_BODY_STATS=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/stats" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    echo "Stats Body:"
    echo "$HTTP_BODY_STATS" | jq .
    # Basic check: Ensure CPU percentage exists
    CPU_PERCENT=$(echo "$HTTP_BODY_STATS" | jq '.data.cpu_percentage')
     if [ -z "$CPU_PERCENT" ] || [ "$CPU_PERCENT" == "null" ]; then
       echo -e "\n--- FAILED: CPU Percentage not found in stats response. ---"
       exit 1
     fi
  else
    echo -e "\n--- FAILED: Did not get 200 OK for getting stats. ---"
    exit 1
  fi
else
  echo "WARN: Skipping stats test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing GET /containers/:id/top ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Get top (default args)
  HTTP_STATUS_TOP=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/top" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_TOP"

  if [ "$HTTP_STATUS_TOP" -eq 200 ]; then # Expect 200 OK
    echo -e "\n--- SUCCESS: Successfully retrieved top for container $NEW_CONTAINER_ID. ---"
    HTTP_BODY_TOP=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/top" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    echo "Top Body:"
    echo "$HTTP_BODY_TOP" | jq .
    # Basic check: Ensure Titles array exists
    TITLES=$(echo "$HTTP_BODY_TOP" | jq '.data.titles')
     if [ -z "$TITLES" ] || [ "$TITLES" == "null" ]; then
       echo -e "\n--- FAILED: Titles not found in top response. ---"
       exit 1
     fi
  else
    echo -e "\n--- FAILED: Did not get 200 OK for getting top. ---"
    exit 1
  fi
else
  echo "WARN: Skipping top test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing GET /containers/:id/changes ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Get changes
  HTTP_STATUS_CHANGES=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/changes" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_CHANGES"

  if [ "$HTTP_STATUS_CHANGES" -eq 200 ]; then # Expect 200 OK
    echo -e "\n--- SUCCESS: Successfully retrieved changes for container $NEW_CONTAINER_ID. ---"
    HTTP_BODY_CHANGES=$(curl -s -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/changes" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    echo "Changes Body:"
    echo "$HTTP_BODY_CHANGES" | jq .
    # Basic check: Ensure data is an array (can be empty)
    CHANGES_TYPE=$(echo "$HTTP_BODY_CHANGES" | jq -r '.data | type')
     if [ "$CHANGES_TYPE" != "array" ]; then
       echo -e "\n--- FAILED: Changes data is not an array. ---"
       exit 1
     fi
  else
    echo -e "\n--- FAILED: Did not get 200 OK for getting changes. ---"
    exit 1
  fi
else
  echo "WARN: Skipping changes test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing GET /containers/:id/files (Download /etc/hostname) ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Ensure container is running for file access
  curl -s -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/start" -H "Authorization: Bearer $ACCESS_TOKEN" > /dev/null
  sleep 1 # Give it a sec to start

  # Get file archive
  HTTP_STATUS_GETFILE=$(curl -s -o downloaded_archive.tar -w "%{http_code}" -X GET "$BASE_URL/containers/$NEW_CONTAINER_ID/files?path=/etc/hostname" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_GETFILE"

  if [ "$HTTP_STATUS_GETFILE" -eq 200 ]; then # Expect 200 OK
    echo -e "\n--- SUCCESS: Successfully downloaded archive for /etc/hostname. ---"
    # Basic check: Ensure the downloaded file is not empty and is a tar archive
    if [ -s downloaded_archive.tar ]; then
        echo "Downloaded archive size: $(ls -l downloaded_archive.tar | awk '{print $5}') bytes"
        # Optional: Verify tar content
        # tar -tvf downloaded_archive.tar
        # HOSTNAME_CONTENT=$(tar -xOf downloaded_archive.tar hostname 2>/dev/null)
        # echo "Extracted hostname: $HOSTNAME_CONTENT"
        # if [ -z "$HOSTNAME_CONTENT" ]; then
        #    echo -e "\n--- FAILED: Could not extract hostname from archive. ---"
        #    exit 1
        # fi
        rm downloaded_archive.tar # Clean up
    else
        echo -e "\n--- FAILED: Downloaded archive is empty. ---"
        exit 1
    fi
  else
    echo -e "\n--- FAILED: Did not get 200 OK for downloading file. ---"
    exit 1
  fi
else
  echo "WARN: Skipping file download test as NEW_CONTAINER_ID was not set."
fi

echo -e "\n--- Testing POST /containers/:id/files (Upload test file) ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Create a dummy file content and pipe it to tar, then to curl
  UPLOAD_CONTENT="Test content for upload $$"
  # Create temp dir and file for macOS compatible tar
  TEMP_UPLOAD_DIR=$(mktemp -d)
  echo "$UPLOAD_CONTENT" > "$TEMP_UPLOAD_DIR/test_upload.txt"
  # Archive the directory, ensuring the path inside the archive is just the filename
  # Set COPYFILE_DISABLE=1 to prevent macOS tar from including extended attributes
  # Set COPYFILE_DISABLE=1 to prevent macOS extended attributes, use simple tar command
  HTTP_STATUS_PUTFILE=$(tar --no-xattr -C "$TEMP_UPLOAD_DIR" -cf - test_upload.txt | curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/files?path=/tmp/" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/x-tar" \
    --data-binary @-) # Read data from stdin
  rm -rf "$TEMP_UPLOAD_DIR" # Clean up temp dir

  echo "Response Status Code: $HTTP_STATUS_PUTFILE"
  # No intermediate file to clean up

  if [ "$HTTP_STATUS_PUTFILE" -eq 200 ]; then # Expect 200 OK
    echo -e "\n--- SUCCESS: Successfully uploaded archive to /tmp/. ---"
    # TODO: Verify file exists inside container using exec or another file download?
  else
    echo -e "\n--- FAILED: Did not get 200 OK for uploading file. ---"
    exit 1
  fi
else
  echo "WARN: Skipping file upload test as NEW_CONTAINER_ID was not set."
fi


echo -e "\n--- Testing DELETE /containers/:id ---"
if [ ! -z "$NEW_CONTAINER_ID" ] && [ "$NEW_CONTAINER_ID" != "null" ]; then
  # Stop first (required unless force=true)
  curl -s -X POST "$BASE_URL/containers/$NEW_CONTAINER_ID/stop" -H "Authorization: Bearer $ACCESS_TOKEN" > /dev/null
  sleep 1

  # Delete
  HTTP_STATUS_DELETE=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE_URL/containers/$NEW_CONTAINER_ID?force=true" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  echo "Response Status Code: $HTTP_STATUS_DELETE"

  if [ "$HTTP_STATUS_DELETE" -eq 204 ]; then # Expect 204 No Content on success
    echo -e "\n--- SUCCESS: Successfully deleted container $NEW_CONTAINER_ID. ---"
  else
    echo -e "\n--- FAILED: Did not get 204 No Content for deleting container. ---"
    exit 1
  fi
else
  echo "WARN: Skipping delete test as NEW_CONTAINER_ID was not set."
fi


echo -e "\n--- Testing Image Endpoints ---"

echo -e "\n--- Testing GET /images ---"
HTTP_STATUS_IMG_LIST=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/images?page=1&page_size=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
HTTP_BODY_IMG_LIST=$(curl -s -X GET "$BASE_URL/images?page=1&page_size=10" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Response Status Code: $HTTP_STATUS_IMG_LIST"
echo "Response Body (first 10):"
echo "$HTTP_BODY_IMG_LIST" | jq .

if [ "$HTTP_STATUS_IMG_LIST" -eq 200 ]; then
  echo -e "\n--- SUCCESS: Successfully listed images. ---"
else
  echo -e "\n--- FAILED: Did not get 200 OK for listing images. ---"
  exit 1
fi

# Find an image ID to test with (e.g., alpine)
ALPINE_IMAGE_ID=$(echo "$HTTP_BODY_IMG_LIST" | jq -r '.data.images[] | select(.repository=="alpine" and .tag=="latest") | .image_id' | head -n 1)

if [ -z "$ALPINE_IMAGE_ID" ] || [ "$ALPINE_IMAGE_ID" == "null" ]; then
  echo "WARN: Could not find alpine:latest image ID from list. Pulling it."
  PULL_PAYLOAD='{"image": "alpine", "tag": "latest"}'
  PULL_RESPONSE=$(curl -s -X POST "$BASE_URL/images/pull" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PULL_PAYLOAD")
  echo "Pull Response: $PULL_RESPONSE"
  ALPINE_IMAGE_ID=$(echo "$PULL_RESPONSE" | jq -r '.data.id') # Get ID from pull response
  if [ -z "$ALPINE_IMAGE_ID" ] || [ "$ALPINE_IMAGE_ID" == "null" ]; then
     echo "FAILED: Could not pull or find alpine:latest image ID."
     exit 1
  fi
  echo "Pulled alpine:latest, ID: $ALPINE_IMAGE_ID"
  sleep 2 # Give docker_test time
fi

echo -e "\n--- Testing GET /images/:id (alpine) ---"
HTTP_STATUS_IMG_GET=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/images/$ALPINE_IMAGE_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
HTTP_BODY_IMG_GET=$(curl -s -X GET "$BASE_URL/images/$ALPINE_IMAGE_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Response Status Code: $HTTP_STATUS_IMG_GET"
echo "Response Body:"
echo "$HTTP_BODY_IMG_GET" | jq .

if [ "$HTTP_STATUS_IMG_GET" -eq 200 ]; then
  echo -e "\n--- SUCCESS: Successfully retrieved image info for $ALPINE_IMAGE_ID. ---"
else
  echo -e "\n--- FAILED: Did not get 200 OK for getting image info. ---"
  exit 1
fi

echo -e "\n--- Testing POST /images/:id/tag (alpine) ---"
NEW_TAG="test-alpine-tag-$$"
TAG_PAYLOAD='{"source_image": "'"$ALPINE_IMAGE_ID"'", "repository": "docker.io/testuser/testrepo", "tag": "'"$NEW_TAG"'"}' # Add source_image, corrected repo
HTTP_STATUS_IMG_TAG=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/images/tag" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$TAG_PAYLOAD") # Use updated payload and route

echo "Response Status Code: $HTTP_STATUS_IMG_TAG"

if [ "$HTTP_STATUS_IMG_TAG" -eq 201 ]; then # Expect 201 Created
  echo -e "\n--- SUCCESS: Successfully tagged image $ALPINE_IMAGE_ID as docker.io/testuser/testrepo:$NEW_TAG. ---"
else
  # Use the corrected route and payload for error reporting too
  HTTP_BODY_IMG_TAG=$(curl -s -X POST "$BASE_URL/images/tag" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$TAG_PAYLOAD")
  echo "Response Body (Error):"
  echo "$HTTP_BODY_IMG_TAG" | jq .
  echo -e "\n--- FAILED: Did not get 201 Created for tagging image. ---"
  exit 1
fi

echo -e "\n--- Testing GET /image-history/:id (alpine) ---" # Updated path in comment
HTTP_STATUS_IMG_HIST=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$BASE_URL/image-history/$ALPINE_IMAGE_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
HTTP_BODY_IMG_HIST=$(curl -s -X GET "$BASE_URL/image-history/$ALPINE_IMAGE_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Response Status Code: $HTTP_STATUS_IMG_HIST"
echo "Response Body:"
echo "$HTTP_BODY_IMG_HIST" | jq .

if [ "$HTTP_STATUS_IMG_HIST" -eq 200 ]; then
  echo -e "\n--- SUCCESS: Successfully retrieved image history for $ALPINE_IMAGE_ID. ---"
else
  echo -e "\n--- FAILED: Did not get 200 OK for getting image history. ---"
  exit 1
fi

echo -e "\n--- Testing DELETE /images/:id (test tag) ---"
HTTP_STATUS_IMG_DEL_TAG=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$BASE_URL/images/docker.io/testuser/testrepo:$NEW_TAG?force=true" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "Response Status Code: $HTTP_STATUS_IMG_DEL_TAG"

if [ "$HTTP_STATUS_IMG_DEL_TAG" -eq 200 ]; then # Expect 200 OK with report
  echo -e "\n--- SUCCESS: Successfully deleted image tag docker.io/testuser/testrepo:$NEW_TAG. ---"
else
  HTTP_BODY_IMG_DEL_TAG=$(curl -s -X DELETE "$BASE_URL/images/docker.io/testuser/testrepo:$NEW_TAG?force=true" \
    -H "Authorization: Bearer $ACCESS_TOKEN")
  echo "Response Body (Error):"
  echo "$HTTP_BODY_IMG_DEL_TAG" | jq .
  echo -e "\n--- FAILED: Did not get 200 OK for deleting image tag. ---"
  exit 1
fi

# Note: We don't delete the original alpine:latest here as it might be needed by other tests or systems.

# TODO: Add tests for Volume endpoints
# TODO: Add tests for Network endpoints
# TODO: Add tests for System endpoints (Info, Ping, Events, Prune)
# TODO: Add tests for Compose endpoints

echo -e "\n--- Basic API Tests Completed Successfully! ---"

# Cleanup: Stop the server started by make dev-start
echo -e "\n--- Stopping development server ---"
if [ -f .server.pid ]; then
    kill $(cat .server.pid) || echo "Server already stopped or PID file invalid."
    rm .server.pid
else
    echo "No server PID file found."
fi

exit 0
