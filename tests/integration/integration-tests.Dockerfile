# Собираем в гошке
FROM golang:1.19.8-alpine as build

WORKDIR /app
COPY . .

ENV CGO_ENABLED=0

CMD go test -v -mod=vendor -tags integration ./tests/integration