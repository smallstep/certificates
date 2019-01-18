#!/bin/sh

# Download the root certificate and set permissions
step ca certificate $COMMON_NAME $CRT $KEY
chmod 644 $CRT $KEY

step ca root $STEP_ROOT
