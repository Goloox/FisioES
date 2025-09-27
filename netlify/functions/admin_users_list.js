// netlify/functions/admin_users_list.js  (ESM)
import { Client } from "pg";
import jwt from "jsonwebtoken";

function getPayload(authHeader) {
  if (!authHeader) return null;
  const [, token] = authHeader.split(" ");
  if (!token) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

export default async function handler(event) {
  const p = getPayload(event.headers.authorization);
  if (!p) return { statusCode: 401, body: "Token inválido" };
  const rolId = p.rol_id ?? p.role_id ?? p.role ?? p.rol ?? null;
  if (rolId !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const qs = event.queryStringParameters || {};
  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "10", 10)));
  const q = (qs.q || "").trim();
  const rol_id = qs.rol_id ? Number(qs.rol_id) : null;
  const activo = qs.activo ? Number(qs.activo) : null;

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
  await client.connect();

  const where = [];
  const args = [];

  if (q) {
    args.push("%" + q.toLowerCase() + "%");
    where.push(`(LOWER(nombre_completo) LIKE $${args.length}
                OR LOWER(correo) LIKE $${args.length}
                OR LOWER(cedula) LIKE $${args.length})`);
  }
  if (rol_id) { args.push(rol_id); where.push(`rol_id = $${args.length}`); }
  if (activo) { args.push(activo); where.push(`activo = $${args.length}`); }

  const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";

  try {
    const totalRes = await client.query(`SELECT COUNT(*)::int AS c FROM fisio.usuario ${whereSql}`, args);
    const total = totalRes.rows[0].c;

    args.push(pageSize, (page - 1) * pageSize);
    const rowsRes = await client.query(
      `SELECT id, nombre_completo, correo, cedula, rol_id, activo, created_at, updated_at
         FROM fisio.usuario
        ${whereSql}
        ORDER BY id DESC
        LIMIT $${args.length - 1} OFFSET $${args.length}`,
      args
    );

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rows: rowsRes.rows, total, page, pageSize }),
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
}
