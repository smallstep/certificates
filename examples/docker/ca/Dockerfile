FROM alpine

ADD step-ca /usr/local/bin/step-ca
COPY pki /run

# Cron && Nginx
CMD ["step-ca", "/run/config/ca.json"]
