FROM smallstep/step-cli

USER root
RUN mkdir -p /var/local/step
ADD crontab /var/spool/cron/crontabs/root
RUN chmod 0644 /var/spool/cron/crontabs/root

COPY entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/crond", "-l", "2", "-f"]
