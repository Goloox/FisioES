// netlify/functions/video_assign_list.js
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
  const me  = Number(claims.id ?? claims.user_id ?? claims.sub);

  const qs = event.queryStringParameters || {};
  const id_usuario = Number(qs.id_usuario || 0);

  // Permitir: ADMIN puede ver cualquiera; cliente solo su propio id
  if (!id_usuario) return { statusCode: 400, body: "id_usuario requerido" };
  if (rol !== 1 && id_usuario !== me) {
    return { statusCode: 403, body: "Solo puedes ver tus asignaciones" };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    // Tabla correcta: fisio.video_asignacion (NO video_asignado)
    const sql = `
      SELECT
        va.id,
        va.id_usuario,
        va.id_video,
        va.observacion,
        va.created_at,
        va.updated_at,
        v.titulo,
        v.objetivo
      FROM fisio.video_asignacion va
      JOIN fisio.video v
        ON v.id = va.id_video     -- ajusta a v.id_video si tu PK es id_video
      WHERE va.id_usuario = $1
      ORDER BY va.updated_at DESC
    `;
    const r = await client.query(sql, [id_usuario]);

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rows: r.rows })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
