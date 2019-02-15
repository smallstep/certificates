const https = require('https');
const tls = require('tls');
const fs = require('fs');

var config = {
    ca: '/var/run/autocert.step.sm/root.crt',
    key: '/var/run/autocert.step.sm/site.key',
    cert: '/var/run/autocert.step.sm/site.crt',
    ciphers: 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2'
};

function createSecureContext() {
    return tls.createSecureContext({
        ca: fs.readFileSync(config.ca),
        key: fs.readFileSync(config.key),
        cert: fs.readFileSync(config.cert),
        ciphers: config.ciphers,
    });
}

var ctx = createSecureContext()

fs.watch(config.cert, (event, filename) => {
    if (event == 'change') {
        ctx = createSecureContext();
    }
});

https.createServer({
    requestCert: true,
    rejectUnauthorized: true,
    SNICallback: (servername, cb) => {
        cb(null, ctx);
    }
}, (req, res) => {
    res.writeHead(200);
    res.end('hello nodejs\n');
}).listen(443);

console.log("Listening on :443 ...");