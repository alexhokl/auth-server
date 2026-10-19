FROM golang:1.26-alpine AS builder

ENV CGO_ENABLED=0
ENV app_name=auth-server
ENV repo=github.com/alexhokl/${app_name}

WORKDIR /go/src/${repo}

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -tags=nomsgpack -trimpath -ldflags="-s -w" -o /go/bin/${app_name}

FROM alpine:3 AS dev

ENV USERNAME=appuser
ENV UID=1001
ENV GROUP=appgroup
ENV HOME=/home/${USERNAME}

RUN addgroup -g ${UID} -S ${GROUP} && adduser -u ${UID} -S -G ${GROUP} ${USERNAME}

WORKDIR $HOME

COPY --from=builder --chown=appuser:appgroup /go/bin/auth-server .
# HTML templates are loaded from ./assets on start-up
COPY --from=builder --chown=appuser:appgroup /go/src/github.com/alexhokl/auth-server/assets ./assets

VOLUME /mnt/keys

EXPOSE 8080

ENTRYPOINT ["./auth-server"]

FROM dev AS production

USER ${USERNAME}
