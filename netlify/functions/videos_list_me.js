// netlify/functions/videos_list_me.js
import { Client } from "pg";
import { requireUserClaims } from "./_auth.js";

export const handler = async (event) => {
  const auth = requireUserClaims(event);
  if (!auth.ok) return { statusCode: auth.statusCode, body: auth.error };
  const { user_id } = auth.claims;

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  try {
    // Unimos la asignación con el video; ordenamos por la fecha más reciente
    const sql = `
      SELECT
        va.id,
        va.id_video,
        va.id_usuario,
        va.observacion,
        va.created_at,
        va.updated_at,
        v.titulo,
        v.objetivo
      FROM fisio.video_asignacion va
      JOIN fisio.video v ON v.id_video = va.id_video
      WHERE va.id_usuario = $1
      ORDER BY COALESCE(va.updated_at, va.created_at) DESC, va.id DESC
    `;
    const r = await client.query(sql, [user_id]);
    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ rows: r.rows })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
