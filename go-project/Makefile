# Define the service name for Docker Compose
SERVICE_NAME = go-api

# Build and start the application using Docker Compose
build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f $(SERVICE_NAME)

# Stop and remove containers
stop:
	docker-compose down

# Clean up by stopping and removing containers and images
clean:
	docker-compose down --volumes --rmi all
