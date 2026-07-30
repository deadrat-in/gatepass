# Build stage
FROM golang:1.25-alpine3.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o gatepass main.go

# Run stage
FROM alpine:3.24
RUN apk --no-cache add ca-certificates
# Create a non-root user and setup a directory for files/database
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/gatepass .
RUN chown -R appuser:appgroup /app

# Create a data directory for SQLite database logs and set permissions
RUN mkdir /data && chown -R appuser:appgroup /data
VOLUME /data
ENV PROXY_LOGS_DB=/data/gatepass.db

USER appuser
EXPOSE 8318
ENTRYPOINT ["./gatepass"]
