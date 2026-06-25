# authd image: just the Go service. Migrations are applied by the compose
# 'migrate' service using psql (the postgres image already ships it), so this
# image carries no migration tooling
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/authd ./cmd/authd

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/authd /usr/local/bin/authd
EXPOSE 8080
CMD ["authd"]
