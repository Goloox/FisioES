// netlify/functions/videos_list_me.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const me = Number(claims.id ?? claims.user_id ?? claims.sub);
  if (!me) return { statusCode: 401, body: "Unauthorized" };

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();

  try {
    const sql = `
      SELECT
        va.id,
        va.id_usuario,
        va.id_video,
        va.observacion,
        va.updated_at,
        v.id_video           AS id_video,
        v.titulo,
        v.objetivo
      FROM fisio.video_asignacion va
      JOIN fisio.video v
        ON v.id_video = va.id_video
      WHERE va.id_usuario = $1
      ORDER BY va.updated_at DESC NULLS LAST, v.titulo ASC
    `;
    const r = await client.query(sql, [me]);

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
