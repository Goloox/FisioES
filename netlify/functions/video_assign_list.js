// netlify/functions/video_assign_list.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };
  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); } catch { return { statusCode: 401, body: "Unauthorized" }; }
  if (Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) !== 1) {
    return { statusCode: 403, body: "Solo ADMIN" };
  }

  const qs = event.queryStringParameters || {};
  const id_usuario = Number(qs.id_usuario || 0);
  if (!id_usuario) return { statusCode: 400, body: "id_usuario requerido" };

  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "10", 10)));

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const tot = await client.query(
      `SELECT COUNT(*)::int AS c FROM fisio.video_asignacion WHERE id_usuario = $1`, [id_usuario]
    );
    const { rows } = await client.query(
      `SELECT a.id, a.observacion, a.created_at, a.updated_at,
              v.id_video, v.titulo, v.objetivo, v.video_url
         FROM fisio.video_asignacion a
         JOIN fisio.video v ON v.id_video = a.id_video
        WHERE a.id_usuario = $1
        ORDER BY a.updated_at DESC
        LIMIT $2 OFFSET $3`,
      [id_usuario, pageSize, (page - 1) * pageSize]
    );
    return { statusCode: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ rows, total: tot.rows[0].c, page, pageSize }) };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
