#!/bin/sh

ulimit -n 65536
/usr/local/bin/envoy -c /src/server.yaml --service-cluster hello-mTLS --restart-epoch $RESTART_EPOCH
