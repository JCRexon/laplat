# authd image: the Go service plus the goose migration tool and the migration
# files. The same image runs two compose services — `migrate` (goose up) and
# `authd` — so the binary and the migrations never drift.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/authd ./cmd/authd
RUN GOBIN=/out go install github.com/pressly/goose/v3/cmd/goose@v3.22.1

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
COPY --from=build /out/authd /usr/local/bin/authd
COPY --from=build /out/goose /usr/local/bin/goose
COPY migrations /migrations
EXPOSE 8080
CMD ["authd"]
