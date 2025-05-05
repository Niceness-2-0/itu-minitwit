#!/bin/bash

# === CONFIG ===
STACK_NAME="myapp"
COMPOSE_FILE="docker-compose.yml"

# Format: "service_name=image_name"
declare -A SERVICES=(
  [api]="alialexandra/api:latest"
  [web]="alialexandra/web:latest"
  [promtail]="alialexandra/promtail:latest"
)

# === FLAGS ===
REDEPLOY_NEEDED=false

for SERVICE in "${!SERVICES[@]}"; do
    IMAGE=${SERVICES[$SERVICE]}

    echo "Checking service: $SERVICE"
    echo "Image: $IMAGE"

    # Pull the latest image
    docker pull "$IMAGE" > /dev/null || {
        echo "Failed to pull image: $IMAGE"
        continue
    }

    # Get currently running image digest
    CURRENT_IMAGE_ID=$(docker service inspect --format='{{.Spec.TaskTemplate.ContainerSpec.Image}}' "${STACK_NAME}_${SERVICE}" | cut -d'@' -f2)

    # Get latest image digest
    LATEST_IMAGE_ID=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null | cut -d'@' -f2)

    echo "Current: $CURRENT_IMAGE_ID"
    echo "Latest:  $LATEST_IMAGE_ID"

    if [[ "$CURRENT_IMAGE_ID" != "$LATEST_IMAGE_ID" ]]; then
        echo "Update needed for $SERVICE"
        REDEPLOY_NEEDED=true
    else
        echo "No update needed for $SERVICE"
    fi

    echo "---------------------------"
done

# === Redeploy if any image changed ===
if [ "$REDEPLOY_NEEDED" = true ]; then
    echo "Changes detected. Redeploying stack..."
    docker stack deploy -c "$COMPOSE_FILE" "$STACK_NAME"
else
    echo "No changes detected. Stack is up to date."
fi
