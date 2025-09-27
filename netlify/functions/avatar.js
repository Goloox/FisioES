// netlify/functions/avatar.js
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

export const handler = async (event) => {
  try {
    const claims = auth(event);
    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    const r = await client.query(`
      SELECT imagen FROM fisio.imagen_usuario
      WHERE usuario_id = $1
      ORDER BY id DESC LIMIT 1
    `, [claims.id]);
    await client.end();

    if (r.rowCount === 0 || !r.rows[0].imagen) {
      return { statusCode: 404, body: "No image" };
    }

    return {
      statusCode: 200,
      headers: { "Content-Type": "image/jpeg", "Cache-Control": "private, max-age=60" },
      body: Buffer.from(r.rows[0].imagen).toString('base64'),
      isBase64Encoded: true
    };
  } catch (e) {
    return { statusCode: 401, body: "Unauthorized" };
  }
};
