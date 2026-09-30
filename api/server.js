const express = require("express");
const tls = require("tls");
const dns = require("dns").promises;

const app = express();

const PORT = process.env.PORT || 3000;

app.use(express.json());

function validHostname(host) {
    if (!host || typeof host !== "string") return false;

    host = host.trim();

    if (host.length > 253) return false;

    return /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)$/.test(host);
}

function cleanHost(value) {
    return String(value || "")
        .trim()
        .replace(/^https?:\/\//i, "")
        .split("/")[0]
        .split(":")[0]
        .toLowerCase();
}

function tlsInspect(host) {
    return new Promise((resolve, reject) => {

        const start = Date.now();

        const socket = tls.connect({
            host,
            port: 443,
            servername: host,
            rejectUnauthorized: false,
            minVersion: "TLSv1.2",
            timeout: 8000
        });

        let finished = false;

        function done(fn, value) {
            if (finished) return;

            finished = true;

            try {
                socket.destroy();
            } catch {}

            fn(value);
        }

        socket.on("secureConnect", async () => {

            try {

                const certificate = socket.getPeerCertificate(true);
                const cipher = socket.getCipher();

                let addresses = [];

                try {
                    addresses = await dns.lookup(host, {
                        all: true
                    });
                } catch {}

                const result = {
                    success: true,

                    host,

                    port: 443,

                    connected: true,

                    responseTimeMs:
                        Date.now() - start,

                    tls: {
                        version:
                            socket.getProtocol() || null,

                        cipher:
                            cipher
                                ? cipher.name
                                : null,

                        cipherVersion:
                            cipher
                                ? cipher.version
                                : null
                    },

                    certificate: {
                        subject:
                            certificate.subject || null,

                        issuer:
                            certificate.issuer || null,

                        validFrom:
                            certificate.valid_from || null,

                        validTo:
                            certificate.valid_to || null,

                        serialNumber:
                            certificate.serialNumber || null,

                        fingerprint:
                            certificate.fingerprint256 || null,

                        subjectAltName:
                            certificate.subjectaltname || null
                    },

                    addresses:
                        addresses.map(item => ({
                            address: item.address,
                            family: item.family
                        }))
                };

                done(resolve, result);

            } catch (error) {

                done(reject, error);
            }
        });

        socket.on("timeout", () => {

            done(
                reject,
                new Error("TLS connection timed out")
            );
        });

        socket.on("error", error => {

            done(reject, error);
        });
    });
}


/*
    Health check
*/

app.get("/", (req, res) => {

    res.json({
        service: "THUGKEED NETWORK TLS Inspector",
        status: "online",
        version: "2.0.0"
    });
});


/*
    TLS inspection endpoint

    Example:

    /api/tls?host=example.com
*/

app.get("/api/tls", async (req, res) => {

    const host = cleanHost(req.query.host);

    if (!validHostname(host)) {

        return res.status(400).json({
            success: false,
            error: "Invalid hostname."
        });
    }

    try {

        const result = await tlsInspect(host);

        res.json(result);

    } catch (error) {

        res.status(502).json({
            success: false,
            host,
            error:
                error && error.message
                    ? error.message
                    : "TLS inspection failed."
        });
    }
});


/*
    Start server
*/

app.listen(PORT, () => {

    console.log(
        `THUGKEED TLS API running on port ${PORT}`
    );
});
