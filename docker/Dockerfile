FROM golang:alpine AS builder

WORKDIR /src
COPY . .

RUN apk add --no-cache curl git make libcap
RUN make V=1 bin/step-ca
RUN setcap CAP_NET_BIND_SERVICE=+eip bin/step-ca

FROM smallstep/step-kms-plugin:cloud AS kms

FROM smallstep/step-cli:latest

COPY --from=builder /src/bin/step-ca /usr/local/bin/step-ca
COPY --from=kms /usr/local/bin/step-kms-plugin /usr/local/bin/step-kms-plugin

USER step

ENV CONFIGPATH="/home/step/config/ca.json"
ENV PWDPATH="/home/step/secrets/password"

VOLUME ["/home/step"]
STOPSIGNAL SIGTERM
HEALTHCHECK CMD step ca health 2>/dev/null | grep "^ok" >/dev/null

COPY docker/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
CMD ["/usr/local/bin/step-ca", "--password-file", "/home/step/secrets/password", "/home/step/config/ca.json"]
