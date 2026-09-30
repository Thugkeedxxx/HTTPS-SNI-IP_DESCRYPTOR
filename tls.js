import tls from "node:tls";
import dns from "node:dns";

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, (err, address) => {
      if (err) reject(err);
      else resolve(address);
    });
  });
}

function inspectTLS(host, port = 443) {
  return new Promise((resolve, reject) => {

    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: 8000
    });

    socket.once("secureConnect", () => {

      const certificate = socket.getPeerCertificate();

      const result = {
        hostname: host,
        port,
        ip: socket.remoteAddress || null,

        tlsVersion:
          socket.getProtocol() || null,

        cipher:
          socket.getCipher()?.name || null,

        sni: host,

        authorized:
          socket.authorized,

        authorizationError:
          socket.authorizationError || null,

        subject:
          certificate?.subject || null,

        issuer:
          certificate?.issuer || null,

        validFrom:
          certificate?.valid_from || null,

        validUntil:
          certificate?.valid_to || null,

        serialNumber:
          certificate?.serialNumber || null,

        fingerprint:
          certificate?.fingerprint256 || null
      };

      socket.end();

      resolve(result);
    });

    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("TLS connection timed out"));
    });

    socket.once("error", err => {
      socket.destroy();
      reject(err);
    });
  });
}

export default async function handler(req, res) {

  res.setHeader(
    "Access-Control-Allow-Origin",
    "*"
  );

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  const host = String(req.query.host || "")
    .trim()
    .toLowerCase();

  if (!host) {
    return res.status(400).json({
      error: "Missing host parameter"
    });
  }

  /*
   * Only accept normal DNS hostnames.
   * This prevents the endpoint from becoming a
   * general-purpose arbitrary network connector.
   */
  const hostnamePattern =
    /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

  if (!hostnamePattern.test(host)) {
    return res.status(400).json({
      error: "Invalid hostname"
    });
  }

  try {

    const ip = await resolveHost(host);

    const result = await inspectTLS(host, 443);

    result.ip = ip;

    return res.status(200).json(result);

  } catch (error) {

    return res.status(502).json({
      error: "TLS inspection failed",
      message: error.message
    });
  }
      }
