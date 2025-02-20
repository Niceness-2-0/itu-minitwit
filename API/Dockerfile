# Use the official Golang image as the base image
FROM golang:1.24

# Set the working directory inside the container
WORKDIR /API


#RUN apk add --no-cache gcc musl-dev sqlite-dev

# Copy the Go modules files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . ./

RUN chmod 666 /API/minitwit.db

#ENV CGO_ENABLED=1
# Build the Go application
RUN go build -o main .

# Expose the port the app runs on
EXPOSE 5000

# Command to run the executable
CMD ["./main"]