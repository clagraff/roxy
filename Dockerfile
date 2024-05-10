FROM golang:1.21 as builder

WORKDIR /app
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o roxy

# Stage 2: Prepare the runtime container
FROM alpine:latest
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/roxy .

# Set the port and run the application
EXPOSE 80
ENTRYPOINT ["./roxy"]