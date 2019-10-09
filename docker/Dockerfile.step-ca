FROM smallstep/step-cli:latest

ARG BINPATH="bin/step-ca"

ENV CONFIGPATH="/home/step/config/ca.json"
ENV PWDPATH="/home/step/secrets/password"

COPY $BINPATH "/usr/local/bin/step-ca"

VOLUME ["/home/step"]
STOPSIGNAL SIGTERM

CMD exec /bin/sh -c "/usr/local/bin/step-ca --password-file $PWDPATH $CONFIGPATH"
