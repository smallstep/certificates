FROM alpine:latest

RUN mkdir -p /var/local/step
ADD step /usr/local/bin/step
ADD crontab /var/spool/cron/crontabs/root
RUN chmod 0644 /var/spool/cron/crontabs/root

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/crond", "-l", "2", "-f"]
