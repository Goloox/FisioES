// netlify/functions/videos_list_me.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

/* --- helpers --- */
function getToken(event){
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  return q.jwt || null;
}
function deepGet(o, path){
  try { return path.split(".").reduce((a,k)=> (a==null? a : a[k]), o); } catch { return undefined; }
}
async function resolveUserId(client, claims){
  // intenta id en varios campos
  for (const p of ["id","user_id","usuario_id","id_usuario","sub","uid","user.id","usuario.id"])
    { const v = deepGet(claims, p); if (v!=null && v!=="") return Number(v); }
  // intenta por email
  for (const p of ["email","correo","mail","user.email","usuario.correo"]){
    const email = deepGet(claims, p);
    if (email){
      const r = await client.query(
        `SELECT id FROM fisio.usuario WHERE LOWER(correo)=LOWER($1) LIMIT 1`, [email]
      );
      if (r.rowCount) return Number(r.rows[0].id);
    }
  }
  return null;
}

/* --- handler --- */
export const handler = async (event) => {
  const token = getToken(event);
  const debug = (event.queryStringParameters||{}).debug === "1";
  if (!token) return { statusCode: 401, body: debug ? "Unauthorized: missing token" : "Unauthorized" };

  let claims;
  try { claims = jwt.verify(token, process.env.JWT_SECRET); }
  catch (e) { return { statusCode: 401, body: debug ? ("Unauthorized: " + e.message) : "Unauthorized" }; }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const userId = await resolveUserId(client, claims);
    if (!userId) return { statusCode: 401, body: debug ? "Unauthorized: could not resolve user id" : "Unauthorized" };

    // OJO: v.id_video (no v.id)
    const sql = `
      SELECT
        va.id               AS id_asignacion,
        va.id_usuario,
        va.id_video,
        va.observacion,
        va.updated_at,
        v.id_video          AS id_video,
        v.titulo,
        v.objetivo
      FROM fisio.video_asignacion va
      JOIN fisio.video v ON v.id_video = va.id_video
      WHERE va.id_usuario = $1
      ORDER BY va.updated_at DESC NULLS LAST, v.titulo ASC
    `;
    const r = await client.query(sql, [userId]);

    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ rows: r.rows })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally { try{ await client.end(); }catch{} }
};
