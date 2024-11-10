FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY templates/ /app/templates/
COPY --from=builder /app/main /app/

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["/app/main"]