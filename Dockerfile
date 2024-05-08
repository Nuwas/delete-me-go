# Start from the latest golang base image
FROM golang:1.22.2 AS build

ENV workspace /hpe/sample_go

COPY go.mod $workspace/
COPY go.sum $workspace/
COPY cmd/ $workspace/cmd/

WORKDIR $workspace/
# Build the Go app with CGO_ENABLED=0 for a statically linked binary
RUN go build -x -o bin/ ./cmd/main.go

FROM debian:latest
#RUN apk add --no-cache bash
RUN echo $workspace
RUN apt-get update && apt-get install -y \
    bash
COPY --from=build /hpe/sample_go/bin/main /main
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["/main"]
