// netlify/functions/change_email.js
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
    const correo = String(body.correo || "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(correo)) return { statusCode: 400, body: JSON.stringify({ error: "Correo inválido" }) };

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();

    // verificar unicidad
    const exists = await client.query(`SELECT 1 FROM fisio.usuario WHERE correo = $1 AND id <> $2`, [correo, claims.id]);
    if (exists.rowCount > 0) {
      await client.end();
      return { statusCode: 409, body: JSON.stringify({ error: "Ese correo ya está en uso" }) };
    }

    const r = await client.query(`
      UPDATE fisio.usuario SET correo = $1
      WHERE id = $2
      RETURNING id, nombre_completo, correo, cedula, rol_id, activo
    `, [correo, claims.id]);

    await client.end();
    return { statusCode: 200, body: JSON.stringify({ usuario: r.rows[0] }) };
  } catch (e) {
    // Si estalla por UNIQUE CONSTRAINT desde DB
    if (String(e.message).includes('unique') || String(e.message).includes('duplicate')) {
      return { statusCode: 409, body: JSON.stringify({ error: "Ese correo ya está en uso" }) };
    }
    return { statusCode: 401, body: JSON.stringify({ error: e.message || "No autorizado" }) };
  }
};
