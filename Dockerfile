# Stage 1: Build the Go application
FROM golang:1.21 as builder

# Set the working directory
WORKDIR /usr/src/app

# Copy go.mod and go.sum files to leverage Docker's caching mechanism
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the application files
COPY . .

# Build the Go application with CGO disabled for a fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/roxy

# Stage 2: Prepare the runtime container
FROM alpine:latest

# Update the Alpine image to ensure it's up to date
RUN apk --no-cache update && apk --no-cache upgrade

# Expose the necessary ports
EXPOSE 80
EXPOSE 443

# Run the application
ENTRYPOINT ["/usr/local/bin/roxy"]
