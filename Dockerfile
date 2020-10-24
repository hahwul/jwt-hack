# BUILDER
FROM golang:latest AS builder
WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go build -o jwt-hack

# RUNNING
FROM debian:buster
RUN mkdir /app
COPY --from=builder /go/src/app/jwt-hack /app/jwt-hack
COPY --from=builder /go/src/app/samples /app/samples
WORKDIR /app/
CMD ["/app/jwt-hack"]
