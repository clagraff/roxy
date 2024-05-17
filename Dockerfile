# Stage 1: Build the Go application
FROM golang:1.21 as builder

# Set the working directory
WORKDIR /usr/src/roxy

# Copy go.mod and go.sum files to leverage Docker's caching mechanism
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the rest of the application files
COPY . .

# Build the Go application with CGO disabled for a fully static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/src/roxy/roxy

# Stage 2: Prepare the runtime container
FROM alpine:latest

# Update the Alpine image to ensure it's up to date and install ca-certificates
RUN apk --no-cache add ca-certificates

# Set the working directory (optional but recommended for clarity)
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /usr/src/roxy/roxy /usr/local/bin/roxy

# Expose the necessary ports
EXPOSE 80
EXPOSE 443

# Run the application
ENTRYPOINT ["/usr/local/bin/roxy"]
