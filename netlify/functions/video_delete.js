// netlify/functions/video_delete.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if (event.httpMethod !== "POST" && event.httpMethod !== "DELETE") {
    return { statusCode: 405, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  // Auth admin
  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Unauthorized" }) };
  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); } catch { return { statusCode: 401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Unauthorized" }) }; }
  if (Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) !== 1) {
    return { statusCode: 403, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Solo ADMIN" }) };
  }

  // payload
  const qs = event.queryStringParameters || {};
  let id_video = qs.id ? Number(qs.id) : null;
  if (!id_video) {
    try {
      const body = JSON.parse(event.body || "{}");
      id_video = Number(body.id_video || 0);
    } catch {}
  }
  if (!id_video) return { statusCode: 400, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "id_video requerido" }) };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const del = await client.query(`DELETE FROM fisio.video WHERE id_video=$1 RETURNING id_video`, [id_video]);
    if (!del.rowCount) return { statusCode: 404, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "No existe" }) };
    // ON DELETE CASCADE eliminará video_archivo y video_asignacion
    return { statusCode: 200, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ok: true, id_video }) };
  } catch (e) {
    return { statusCode: 500, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Error: " + e.message }) };
  } finally {
    try { await client.end(); } catch {}
  }
};
