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

  const usuario_id = Number(claims.id || claims.user_id || claims.sub || claims.usuario_id);
  if (!usuario_id) return { statusCode: 400, body: "usuario no válido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    // Ajusta los nombres de tabla/campos a tu esquema real
    const r = await client.query(
      `SELECT va.id_asignacion, va.id_video, va.observacion, va.updated_at,
              v.titulo, v.objetivo
         FROM fisio.video_asignado va
         JOIN fisio.video v ON v.id_video = va.id_video
        WHERE va.id_usuario = $1
        ORDER BY va.updated_at DESC`,
      [usuario_id]
    );

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
