# Define the service name for Docker Compose
SERVICE_NAME = go-api

# Build and start the application using Docker Compose
build:
	docker-compose build

up:
	docker-compose up -d

# Stop and remove containers
down:
	docker-compose down

logs:
	docker-compose logs -f $(SERVICE_NAME)

# Stop but don't remove the containers
stop:
	docker-compose stop

# Clean up by stopping and removing containers and images
clean:
	docker-compose down --volumes --rmi all
