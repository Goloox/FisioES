// netlify/functions/video_stream.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

function getToken(event) {
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  return q.jwt || null;
}

function bufferFromPg(raw) {
  if (!raw) return null;
  if (Buffer.isBuffer(raw)) return raw;
  if (raw?.type === "Buffer" && Array.isArray(raw?.data)) return Buffer.from(raw.data);
  if (typeof raw === "string" && raw.startsWith("\\x")) return Buffer.from(raw.slice(2), "hex");
  if (typeof raw === "string") return Buffer.from(raw, "base64");
  try { return Buffer.from(raw); } catch { return null; }
}

export const handler = async (event) => {
  // --- auth ---
  const token = getToken(event);
  if (!token) return { statusCode: 401, body: "Unauthorized" };
  let claims;
  try { claims = jwt.verify(token, process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const role = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  const userId = Number(claims.id ?? claims.user_id ?? claims.usuario_id ?? claims.sub);

  const idVideo = Number((event.queryStringParameters || {}).id || 0);
  if (!idVideo) return { statusCode: 400, body: "id requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();

  try {
    // --- Permisos: admin o usuario con asignación ---
    if (role !== 1) {
      const check = await client.query(
        `SELECT 1 FROM fisio.video_asignacion WHERE id_usuario=$1 AND id_video=$2 LIMIT 1`,
        [userId, idVideo]
      );
      if (check.rowCount === 0) return { statusCode: 403, body: "Forbidden" };
    }

    // --- Intentar leer binario desde video_archivo ---
    const fileRes = await client.query(
      `SELECT archivo, COALESCE(content_type,'video/mp4') AS content_type
         FROM fisio.video_archivo
        WHERE id_video=$1
        LIMIT 1`,
      [idVideo]
    );

    if (fileRes.rowCount > 0) {
      const row = fileRes.rows[0];
      const full = bufferFromPg(row.archivo);
      if (!full) return { statusCode: 500, body: "Archivo inválido" };

      const total = full.length;
      const range = event.headers?.range;
      const ct = row.content_type || "video/mp4";

      // Soporte Range
      if (range && /^bytes=/.test(range)) {
        const [startStr, endStr] = range.replace(/bytes=/, "").split("-");
        let start = parseInt(startStr, 10);
        let end = endStr ? parseInt(endStr, 10) : total - 1;
        if (isNaN(start) || start < 0) start = 0;
        if (isNaN(end) || end >= total) end = total - 1;
        if (start > end) start = 0;

        const chunk = full.subarray(start, end + 1);
        return {
          statusCode: 206,
          isBase64Encoded: true,
          headers: {
            "Content-Type": ct,
            "Content-Length": String(chunk.length),
            "Accept-Ranges": "bytes",
            "Content-Range": `bytes ${start}-${end}/${total}`,
            "Cache-Control": "private, max-age=60"
          },
          body: chunk.toString("base64")
        };
      }

      // Respuesta completa
      return {
        statusCode: 200,
        isBase64Encoded: true,
        headers: {
          "Content-Type": ct,
          "Content-Length": String(total),
          "Accept-Ranges": "bytes",
          "Cache-Control": "private, max-age=60"
        },
        body: full.toString("base64")
      };
    }

    // --- Si no hay binario, intentar URL externa (redirigir) ---
    const vRes = await client.query(`SELECT video_url FROM fisio.video WHERE id_video=$1 LIMIT 1`, [idVideo]);
    if (vRes.rowCount) {
      const url = vRes.rows[0].video_url || "";
      if (/^https?:\/\//i.test(url)) {
        return {
          statusCode: 302,
          headers: { Location: url }
        };
      }
    }

    return { statusCode: 404, body: "Video no disponible" };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
