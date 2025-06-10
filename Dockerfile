# Use the official Golang image as the base image
FROM golang:1.24 as builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go modules manifests
COPY go.mod go.sum ./

# Download the Go module dependencies
RUN go mod download

# Copy the application source code
COPY . .

# Build the application
RUN go build -o dns-server .

# Use a minimal base image for the final container
FROM debian:bookworm-slim
ENV DETECTION_API=http://localhost:8080
# Set the working directory inside the container
WORKDIR /app

# Copy the built application from the builder stage
COPY --from=builder /app/dns-server .

# Expose the DNS port
EXPOSE 53/udp

# Command to run the application
CMD ["./dns-server"]