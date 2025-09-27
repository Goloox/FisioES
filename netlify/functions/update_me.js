// netlify/functions/update_me.js
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
    if (event.httpMethod !== "POST") return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };

    const claims = auth(event);
    const body = JSON.parse(event.body || "{}");
    const nombre = String(body.nombre_completo || "").trim();
    if (!nombre || nombre.length < 3) return { statusCode: 400, body: JSON.stringify({ error: "Nombre inválido" }) };

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();
    const r = await client.query(`
      UPDATE fisio.usuario SET nombre_completo = $1
      WHERE id = $2
      RETURNING id, nombre_completo, correo, cedula, rol_id, activo
    `, [nombre, claims.id]);
    await client.end();

    return { statusCode: 200, body: JSON.stringify({ usuario: r.rows[0] }) };
  } catch (e) {
    return { statusCode: 401, body: JSON.stringify({ error: e.message || "No autorizado" }) };
  }
};
