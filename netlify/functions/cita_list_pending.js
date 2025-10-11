// netlify/functions/cita_list_pending.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const qs = event.queryStringParameters || {};
  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "50", 10)));

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    // Pendientes = estado = 3 (En espera)
    const totalRes = await client.query(
      `SELECT COUNT(*)::int c
         FROM fisio.cita ci
         JOIN fisio.usuario u ON u.id = ci.usuario_id
        WHERE ci.estado = 3`
    );
    const total = totalRes.rows[0].c;

    const rowsRes = await client.query(
      `SELECT ci.id_cita, ci.usuario_id, ci.fecha, ci.estado, ci.titulo, ci.descripcion,
              u.nombre_completo, u.correo
         FROM fisio.cita ci
         JOIN fisio.usuario u ON u.id = ci.usuario_id
        WHERE ci.estado = 3
        ORDER BY ci.fecha ASC
        LIMIT $1 OFFSET $2`,
      [pageSize, (page-1)*pageSize]
    );

    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ rows: rowsRes.rows, total, page, pageSize })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
