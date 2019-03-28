FROM smallstep/step-cli:0.9.0

ENV CA_NAME="Autocert"
ENV CA_DNS="ca.step.svc.cluster.local,127.0.0.1"
ENV CA_ADDRESS=":4443"
ENV CA_DEFAULT_PROVISIONER="admin"
ENV CA_URL="ca.step.svc.cluster.local"

ENV KUBE_LATEST_VERSION="v1.14.0"

USER root
RUN curl -L https://storage.googleapis.com/kubernetes-release/release/${KUBE_LATEST_VERSION}/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl \
 && chmod +x /usr/local/bin/kubectl
RUN apk --update add expect

COPY autocert.sh /home/step/
RUN chmod +x /home/step/autocert.sh
CMD ["/home/step/autocert.sh"]
