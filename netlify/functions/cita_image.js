// netlify/functions/cita_image.js
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
  if (buf[0]===0xFF && buf[1]===0xD8) return "image/jpeg";
  if (buf[0]===0x89 && buf[1]===0x50 && buf[2]===0x4E && buf[3]===0x47) return "image/png";
  if (buf[0]===0x47 && buf[1]===0x49 && buf[2]===0x46) return "image/gif";
  return "image/jpeg";
}

export const handler = async (event) => {
  const token = getToken(event);
  if(!token) return { statusCode: 401, body: "Unauthorized" };
  let claims; try{ claims = jwt.verify(token, process.env.JWT_SECRET); } catch { return { statusCode: 401, body: "Unauthorized" }; }

  const role = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  if (role !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const id = Number((event.queryStringParameters||{}).id || 0);
  if (!id) return { statusCode: 400, body: "id requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const r = await client.query(`SELECT imagen FROM fisio.imagenes_cita WHERE id=$1 LIMIT 1`, [id]);
    if (!r.rowCount) return { statusCode: 404, body: "No existe" };
    const raw = r.rows[0].imagen;
    const buf = Buffer.isBuffer(raw) ? raw
      : (raw?.type==="Buffer" && Array.isArray(raw?.data)) ? Buffer.from(raw.data)
      : typeof raw === "string" && raw.startsWith("\\x") ? Buffer.from(raw.slice(2), "hex")
      : Buffer.from(raw);
    const ct = sniff(buf);
    return {
      statusCode: 200,
      headers: { "Content-Type": ct, "Cache-Control":"private, max-age=300" },
      isBase64Encoded: true,
      body: buf.toString('base64')
    };
  }catch(e){
    return { statusCode: 500, body: "Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
