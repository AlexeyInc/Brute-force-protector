FROM golang:1.17.8-alpine as build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . ./

ARG LDFLAGS
RUN CGO_ENABLED=0 GOOS=linux go build \
        -ldflags "$LDFLAGS" \
        -o bf-protector cmd/bf-protector/*

FROM alpine:3.16

ENV BIN_FILE "/app/bf-protector"
COPY --from=build ${BIN_FILE} ${BIN_FILE}

ENV CONFIG_FILE /config/config.toml
COPY ./configs/bf-protector_config.toml ${CONFIG_FILE}

ENV LOG_FILE /log/logs.log
COPY ./log/logs.log ${LOG_FILE}

EXPOSE 8081

CMD ${BIN_FILE} -config ${CONFIG_FILE} -log ${LOG_FILE}
