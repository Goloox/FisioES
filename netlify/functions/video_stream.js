// netlify/functions/videos_list_me.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

// Obtener token desde Authorization: Bearer ... o ?jwt=...
function getToken(event){
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  return q.jwt || null;
}

// Resolver id de usuario desde los claims; si no hay, intentar por correo
async function resolveUserId(client, claims){
  // 1) Campos típicos de id en el JWT
  const direct =
    claims.id ?? claims.user_id ?? claims.sub ?? claims.uid ??
    claims.usuario_id ?? claims.id_usuario ?? null;
  if (direct) return Number(direct);

  // 2) Buscar por correo en BD (si viene en el token)
  const email = claims.email ?? claims.correo ?? claims.mail ?? null;
  if (email) {
    const r = await client.query(
      `SELECT id FROM fisio.usuario WHERE LOWER(correo)=LOWER($1) LIMIT 1`,
      [String(email)]
    );
    if (r.rowCount) return Number(r.rows[0].id);
  }

  // 3) No se pudo resolver
  return null;
}

export const handler = async (event) => {
  const token = getToken(event);
  if (!token) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();

  try {
    const me = await resolveUserId(client, claims);
    if (!me) return { statusCode: 401, body: "Unauthorized" };

    // Traer asignaciones y metadatos del video
    const sql = `
      SELECT
        va.id,
        va.id_usuario,
        va.id_video,
        va.observacion,
        va.updated_at,
        v.id_video AS id_video,
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
