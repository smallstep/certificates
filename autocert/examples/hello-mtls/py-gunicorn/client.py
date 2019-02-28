#!/usr/bin/env python
import os
import sys
import ssl
import signal
import time
import logging
import threading
import http.client
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from urllib.parse import urlparse

ca_certs = '/var/run/autocert.step.sm/root.crt'
cert_file = '/var/run/autocert.step.sm/site.crt'
key_file = '/var/run/autocert.step.sm/site.key'

# RenewHandler is an even file system event handler that reloads the certs in
# the context when a file is modified.
class RenewHandler(FileSystemEventHandler):
    def __init__(self, ctx):
        self.ctx = ctx
        super().__init__()

    def on_modified(self, event):
        logging.info("reloading certs ...")
        ctx.load_cert_chain(cert_file, key_file)

# Monitor is a thread that watches for changes in a path and calls to the
# RenewHandler when a file is modified.
class Monitor(threading.Thread):
    def __init__(self, handler, path):
        super().__init__()
        self.handler = handler
        self.path = path

    def run(self):
        observer = Observer()
        observer.schedule(self.handler, self.path)
        observer.start()

# Signal handler
def handler(signum, frame):
    print("exiting ...")
    sys.exit(0)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

    # Start signal handler to exit
    signal.signal(signal.SIGTERM, handler)

    # url from the environment
    url = urlparse(os.environ['HELLO_MTLS_URL'])
    
    # ssl context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.set_ciphers('ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256')
    ctx.load_verify_locations(ca_certs)
    ctx.load_cert_chain(cert_file, key_file)

    # initialize the renewer with the ssl context
    renewer = RenewHandler(ctx)

    # start file monitor
    monitor = Monitor(renewer, os.path.dirname(cert_file))
    monitor.start()

    # Do requests
    while True:
        try:
            conn = http.client.HTTPSConnection(url.netloc, context=ctx)
            conn.request("GET", url.path)
            r = conn.getresponse()
            data = r.read()
            logging.info("%d - %s - %s", r.status, r.reason, data)
        except Exception as err:
            print('Something went wrong:', err)
        time.sleep(5)
