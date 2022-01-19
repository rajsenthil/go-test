FROM golang:1.13.8 as golang1
WORKDIR src
COPY instrumenting.go .
COPY logging.go .
COPY service.go .
COPY transport.go .
COPY main.go .
RUN go mod init hello.com/hello/v2
RUN rm go.mod
RUN go get -u github.com/go-kit/kit/endpoint
RUN go get -u github.com/go-kit/log
RUN go get -u github.com/prometheus/client_golang/prometheus
RUN go get -u github.com/prometheus/client_golang/prometheus/promhttp
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /hello

FROM scratch
COPY --from=golang1 /hello /hello
ENTRYPOINT ["/hello"]
