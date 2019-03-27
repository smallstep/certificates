FROM smallstep/step-cli:0.9.0

USER root
ENV CRT="/var/run/autocert.step.sm/site.crt"
ENV KEY="/var/run/autocert.step.sm/site.key"
ENV STEP_ROOT="/var/run/autocert.step.sm/root.crt"

ENTRYPOINT ["/bin/bash", "-c", "step ca renew --daemon $CRT $KEY"]
