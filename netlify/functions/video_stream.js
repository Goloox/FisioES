// netlify/functions/video_stream.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

function getToken(event){
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah && ah.startsWith("Bearer ")) return ah.slice(7);
  return q.jwt || null;
}
function bufferFromPg(raw){
  if (!raw) return null;
  if (Buffer.isBuffer(raw)) return raw;
  if (raw?.type==="Buffer" && Array.isArray(raw?.data)) return Buffer.from(raw.data);
  if (typeof raw === "string" && raw.startsWith("\\x")) return Buffer.from(raw.slice(2), "hex");
  if (typeof raw === "string") return Buffer.from(raw, "base64");
  try { return Buffer.from(raw); } catch { return null; }
}
function cors(h={}) {
  return {
    ...h,
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Range,Content-Type"
  };
}

export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers: cors(), body: "" };

  const token = getToken(event);
  if (!token) return { statusCode: 401, headers: cors(), body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return { statusCode: 401, headers: cors(), body: "Unauthorized" }; }

  const role   = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  const userId = Number(claims.id ?? claims.user_id ?? claims.usuario_id ?? claims.sub);
  const idVideo = Number((event.queryStringParameters||{}).id || 0);
  if (!idVideo) return { statusCode: 400, headers: cors(), body: "id requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();

  try {
    // Permiso: admin o video asignado al usuario
    if (role !== 1) {
      const chk = await client.query(
        `SELECT 1 FROM fisio.video_asignacion WHERE id_usuario=$1 AND id_video=$2 LIMIT 1`,
        [userId, idVideo]
      );
      if (!chk.rowCount) return { statusCode: 403, headers: cors(), body: "Forbidden" };
    }

    // 1) Binario en DB (fisio.video_archivo)
    const fa = await client.query(
      `SELECT archivo, COALESCE(content_type,'video/mp4') AS content_type
         FROM fisio.video_archivo
        WHERE id_video=$1
        LIMIT 1`, [idVideo]
    );

    if (fa.rowCount) {
      const buf = bufferFromPg(fa.rows[0].archivo);
      if (!buf) return { statusCode: 500, headers: cors(), body: "Archivo inválido" };

      const total = buf.length;
      const ct = fa.rows[0].content_type || "video/mp4";
      const range = event.headers?.range;

      if (range && /^bytes=/.test(range)) {
        const [s, e] = range.replace(/bytes=/,'').split('-');
        let start = parseInt(s,10); let end = e ? parseInt(e,10) : total-1;
        if (isNaN(start) || start < 0) start = 0;
        if (isNaN(end) || end >= total) end = total-1;
        if (start > end) start = 0;
        const chunk = buf.subarray(start, end+1);
        return {
          statusCode: 206,
          isBase64Encoded: true,
          headers: cors({
            "Content-Type": ct,
            "Content-Length": String(chunk.length),
            "Accept-Ranges": "bytes",
            "Content-Range": `bytes ${start}-${end}/${total}`,
            "Cache-Control": "private, max-age=60"
          }),
          body: chunk.toString("base64")
        };
      }

      return {
        statusCode: 200,
        isBase64Encoded: true,
        headers: cors({
          "Content-Type": ct,
          "Content-Length": String(total),
          "Accept-Ranges": "bytes",
          "Cache-Control": "private, max-age=60"
        }),
        body: buf.toString("base64")
      };
    }

    // 2) Fallback a URL en fisio.video.video_url (http/https o relativa)
    const v = await client.query(`SELECT video_url FROM fisio.video WHERE id_video=$1 LIMIT 1`, [idVideo]);
    if (v.rowCount) {
      let url = (v.rows[0].video_url || "").trim();

      // evita loop si accidentalmente apunta a esta misma función
      if (url.includes("video_stream")) {
        return { statusCode: 404, headers: cors(), body: "Video no disponible (URL apunta a sí mismo)" };
      }

      // normaliza relativas (./netlify/... -> /netlify/...)
      if (url && !/^https?:\/\//i.test(url)) {
        url = "/" + url.replace(/^\.?\//, "");
      }

      if (url) return { statusCode: 302, headers: cors({ Location: url }), body: "" };
    }

    return { statusCode: 404, headers: cors(), body: "Video no disponible" };
  } catch (e) {
    return { statusCode: 500, headers: cors(), body: "Error: " + e.message };
  } finally { try { await client.end(); } catch {} }
};
