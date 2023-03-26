FROM golang:1.20-alpine3.17 AS builder

RUN apk update && apk upgrade && \
    apk add --no-cache git build-base

ENV CGO_ENABLED=1
ENV app_name auth-server
ENV repo github.com/alexhokl/${app_name}

WORKDIR /go/src/${repo}

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go install -tags musl

FROM alpine:3.17 AS dev

ENV USERNAME=appuser
ENV UID=1001
ENV GROUP=appgroup
ENV HOME=/home/${USERNAME}

RUN addgroup -g ${UID} -S ${GROUP} && adduser -u ${UID} -S -G ${GROUP} ${USERNAME}

WORKDIR $HOME

COPY --from=builder --chown=appuser:appgroup /go/bin/${app_name} .

VOLUME /mnt/keys

EXPOSE 3000

ENTRYPOINT ["./auth-server"]

FROM dev AS production

USER ${USERNAME}

FROM builder AS doc-builder

RUN go get -u github.com/go-swagger/go-swagger/cmd/swagger

RUN swagger generate spec -o ./swagger.json

FROM swaggerapi/swagger-ui:latest AS doc-ui

COPY --from=doc-builder /go/src/github.com/alexhokl/${app_name}/swagger.json /usr/share/nginx/html/swagger.json

