// netlify/functions/video_assign.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method not allowed" };

  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };
  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); } catch { return { statusCode: 401, body: "Unauthorized" }; }
  if (Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) !== 1) {
    return { statusCode: 403, body: "Solo ADMIN" };
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }
  const { id_usuario, id_video, observacion } = body;
  if (!id_usuario || !id_video) return { statusCode: 400, body: "Faltan id_usuario e id_video" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    // upsert por UNIQUE (id_video, id_usuario)
    const { rows } = await client.query(
      `INSERT INTO fisio.video_asignacion (id_video, id_usuario, observacion, created_at, updated_at)
       VALUES ($1,$2,$3, now(), now())
       ON CONFLICT (id_video, id_usuario)
       DO UPDATE SET observacion = EXCLUDED.observacion, updated_at = now()
       RETURNING id, id_video, id_usuario, observacion, created_at, updated_at`,
      [id_video, id_usuario, observacion || null]
    );
    return { statusCode: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify(rows[0]) };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
