// netlify/functions/video_stream.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

function getToken(event){
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  return q.jwt || null;
}
function sniff(buf){
  if (!buf || buf.length < 4) return "application/octet-stream";
  // MP4
  if (buf[4]===0x66 && buf[5]===0x74 && buf[6]===0x79 && buf[7]===0x70) return "video/mp4";
  // WebM
  if (buf[0]===0x1A && buf[1]===0x45 && buf[2]===0xDF && buf[3]===0xA3) return "video/webm";
  // OGG
  if (buf[0]===0x4F && buf[1]===0x67 && buf[2]===0x67 && buf[3]===0x53) return "video/ogg";
  return "application/octet-stream";
}
function toBuffer(raw){
  if (Buffer.isBuffer(raw)) return raw;
  if (raw?.type==="Buffer" && Array.isArray(raw?.data)) return Buffer.from(raw.data);
  if (typeof raw === "string" && raw.startsWith("\\x")) return Buffer.from(raw.slice(2), "hex");
  if (typeof raw === "string") return Buffer.from(raw, "binary");
  return Buffer.from(raw);
}

export const handler = async (event) => {
  const token = getToken(event);
  if(!token) return { statusCode: 401, body: "Unauthorized" };
  let claims; try{ claims = jwt.verify(token, process.env.JWT_SECRET); } catch { return { statusCode: 401, body: "Unauthorized" }; }

  // Cualquier usuario logueado puede reproducir sus videos; el control de pertenencia
  // lo llevas en el frontend (solo lista los suyos). Si quieres reforzar aquí,
  // puedes verificar que el video esté asignado a "claims.id" antes de servirlo.

  const id = Number((event.queryStringParameters||{}).id || 0);
  if (!id) return { statusCode: 400, body: "id requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    // 1) ¿tiene URL pública?
    const v = await client.query(`SELECT id, public_url FROM fisio.video WHERE id=$1 LIMIT 1`, [id]);
    if (v.rowCount && v.rows[0].public_url) {
      return {
        statusCode: 302,
        headers: { Location: v.rows[0].public_url }
      };
    }

    // 2) Buscar archivo binario
    const r = await client.query(`
      SELECT archivo, mime_type, file_name
      FROM fisio.video_archivo
      WHERE id_video=$1
      ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST
      LIMIT 1
    `, [id]);

    if (!r.rowCount) return { statusCode: 404, body: "No hay archivo para este video" };

    const row = r.rows[0];
    const buf = toBuffer(row.archivo);
    const ct  = row.mime_type || sniff(buf);

    return {
      statusCode: 200,
      headers: {
        "Content-Type": ct,
        "Content-Disposition": `inline; filename="${(row.file_name||'video')}"`,
        "Cache-Control": "private, max-age=300"
      },
      isBase64Encoded: true,
      body: buf.toString("base64")
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
