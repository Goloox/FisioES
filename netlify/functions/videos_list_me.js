// netlify/functions/videos_list_me.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

function getToken(event) {
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  return q.jwt || null;
}

export const handler = async (event) => {
  const token = getToken(event);
  if (!token) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const userId = Number(claims.id ?? claims.user_id ?? claims.usuario_id ?? claims.sub);
  if (!userId) return { statusCode: 401, body: "Unauthorized" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const sql = `
      SELECT 
        va.id                 AS id_asignacion,
        va.id_video,
        va.id_usuario,
        va.observacion,
        va.updated_at,
        v.titulo,
        v.objetivo
      FROM fisio.video_asignacion va
      JOIN fisio.video v ON v.id_video = va.id_video
      WHERE va.id_usuario = $1
      ORDER BY va.updated_at DESC, va.id DESC
    `;
    const r = await client.query(sql, [userId]);

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
