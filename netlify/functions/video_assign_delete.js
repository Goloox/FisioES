// netlify/functions/video_assign_delete.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if (event.httpMethod !== "POST" && event.httpMethod !== "DELETE") {
    return { statusCode: 405, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Unauthorized" }) };
  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); } catch { return { statusCode: 401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Unauthorized" }) }; }
  if (Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) !== 1) {
    return { statusCode: 403, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Solo ADMIN" }) };
  }

  let id_usuario = null, id_video = null;
  try{
    const body = event.body ? JSON.parse(event.body) : {};
    id_usuario = Number(body.id_usuario || 0);
    id_video = Number(body.id_video || 0);
  }catch{}

  if (!id_usuario || !id_video) {
    // También acepta por query
    const qs = event.queryStringParameters || {};
    id_usuario = id_usuario || Number(qs.id_usuario || 0);
    id_video   = id_video   || Number(qs.id_video   || 0);
  }
  if (!id_usuario || !id_video) {
    return { statusCode: 400, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "id_usuario y id_video requeridos" }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const del = await client.query(
      `DELETE FROM fisio.video_asignacion WHERE id_usuario=$1 AND id_video=$2 RETURNING id`,
      [id_usuario, id_video]
    );
    if (!del.rowCount) return { statusCode: 404, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "No existe asignación" }) };
    return { statusCode: 200, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ok:true, id_usuario, id_video }) };
  } catch (e) {
    return { statusCode: 500, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Error: " + e.message }) };
  } finally {
    try { await client.end(); } catch {}
  }
};
