// netlify/functions/upload_avatar.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

const { DATABASE_URL, JWT_SECRET } = process.env;

function auth(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) throw new Error("No autorizado");
  const token = auth.slice("Bearer ".length).trim();
  return jwt.verify(token, JWT_SECRET);
}

function extractBase64(dataUrlOrB64) {
  // Si viene como data URL, separar:
  const comma = dataUrlOrB64.indexOf(',');
  if (dataUrlOrB64.startsWith('data:') && comma > -1) {
    return dataUrlOrB64.slice(comma + 1);
  }
  return dataUrlOrB64;
}

export const handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };
    const claims = auth(event);

    const body = JSON.parse(event.body || "{}");
    const raw = String(body.image_base64 || "");
    if (!raw) return { statusCode: 400, body: JSON.stringify({ error: "Imagen requerida" }) };

    const base64 = extractBase64(raw);
    const buffer = Buffer.from(base64, 'base64');

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    await client.query(`
      INSERT INTO fisio.imagen_usuario (usuario_id, imagen)
      VALUES ($1, $2)
    `, [claims.id, buffer]);
    await client.end();

    return { statusCode: 200, body: JSON.stringify({ ok: true }) };
  } catch (e) {
    return { statusCode: 401, body: JSON.stringify({ error: e.message || "No autorizado" }) };
  }
};
