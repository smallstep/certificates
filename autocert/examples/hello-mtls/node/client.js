const fs = require('fs'); 
const https = require('https'); 

const config = {
    ca: '/var/run/autocert.step.sm/root.crt',
    key: '/var/run/autocert.step.sm/site.key',
    cert: '/var/run/autocert.step.sm/site.crt',
    url: process.env.HELLO_MTLS_URL,
    requestFrequency: 5000
};

var options = { 
    ca: fs.readFileSync(config.ca), 
    key: fs.readFileSync(config.key),
    cert: fs.readFileSync(config.cert),
    ciphers: 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    // Not necessary as it defaults to true
    rejectUnauthorized: true
};

fs.watch(config.cert, (event, filename) => {
    if (event == 'change') {
        options.cert = fs.readFileSync(config.cert);
    }
});

function loop() {
    var req = https.request(config.url, options, function(res) { 
        res.on('data', (data) => {
            process.stdout.write(options.cert)
            process.stdout.write(data)
            setTimeout(loop, config.requestFrequency);
        }); 
    }); 
    req.on('error', (e) => {
        process.stderr.write('error: ' + e.message + '\n');
        setTimeout(loop, config.requestFrequency);
    })
    req.end();
}

loop();
