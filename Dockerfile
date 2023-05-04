# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM golang:1.18-alpine AS builder


WORKDIR /

ENV CGO_ENABLED 0
ENV GOPATH /go
ENV GOCACHE /go-build

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/cache \
    go mod download

RUN apk add --update alpine-sdk bash

COPY . /src/music

WORKDIR /src/music

RUN make all

WORKDIR /src/music/musicd/
RUN make && make install


CMD ["/sbin/musicd"]
#CMD ["/bin/bash", "--login"]
