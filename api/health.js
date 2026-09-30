export default function handler(req, res) {
  res.status(200).json({
    status: "online",
    service: "THUGKEED NETWORK API",
    version: "1.0.0"
  });
}
