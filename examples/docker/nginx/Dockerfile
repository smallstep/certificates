FROM nginx:alpine

RUN apk add inotify-tools
RUN mkdir -p /var/local/step
COPY site.conf /etc/nginx/conf.d/
COPY certwatch.sh /
COPY entrypoint.sh /

# Cron && Nginx
ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
