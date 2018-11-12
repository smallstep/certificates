FROM alpine

ADD step-ca /usr/local/bin/step-ca
COPY pki /run

# Smallstep CA
CMD ["step-ca", "/run/config/ca.json"]
