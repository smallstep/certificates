# build stage
FROM golang:alpine AS build-env
RUN apk update && apk upgrade && \
    apk add --no-cache git
RUN go get -u github.com/golang/dep/cmd/dep
WORKDIR $GOPATH/src/github.com/step-certificates-k8s/controller
# copy dep files and run dep separately from code for better caching
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure --vendor-only
COPY . ./
RUN go build -o /server .

# final stage
FROM smallstep/step-cli:0.10.1
ENV STEPPATH="/home/step"
ENV PWDPATH="/home/step/password/password"
ENV CONFIGPATH="/home/step/autocert/config.yaml"
COPY --from=build-env /server .
ENTRYPOINT ./server $CONFIGPATH
