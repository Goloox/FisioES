// netlify/functions/video_stream.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

function getClaims(event) {
  const qs = event.queryStringParameters || {};
  const h  = event.headers || {};
  const headerAuth = h.authorization || h.Authorization || "";
  const queryJwt = qs.jwt;
  let token = null;
  if (headerAuth?.startsWith?.("Bearer ")) token = headerAuth.slice(7);
  else if (queryJwt) token = queryJwt;
  if (!token) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

export const handler = async (event) => {
  const qs = event.queryStringParameters || {};
  const id = Number(qs.id || 0);
  if (!id) return { statusCode: 400, body: "id requerido" };

  const claims = getClaims(event);
  if (!claims) return { statusCode: 401, body: "Unauthorized" };

  const claimUserId = Number(claims.usuario_id ?? claims.user_id ?? claims.id ?? claims.sub);
  const role = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    if (role !== 1) {
      const chk = await client.query(
        `SELECT 1 FROM fisio.video_asignacion WHERE id_video=$1 AND id_usuario=$2 LIMIT 1`,
        [id, claimUserId]
      );
      if (chk.rowCount === 0) return { statusCode: 403, body: "Prohibido" };
    }

    const r = await client.query(
      `SELECT filename, mime_type, size_bytes, archivo
         FROM fisio.video_archivo
        WHERE id_video = $1
        LIMIT 1`,
      [id]
    );
    if (!r.rowCount) return { statusCode: 404, body: "No existe" };

    const { filename, mime_type, archivo } = r.rows[0];

    // Normaliza a Buffer (PG puede devolver Buffer o hex)
    const fullBuf = Buffer.isBuffer(archivo)
      ? archivo
      : (archivo?.type === "Buffer" && Array.isArray(archivo?.data))
        ? Buffer.from(archivo.data)
        : typeof archivo === "string" && archivo.startsWith("\\x")
          ? Buffer.from(archivo.slice(2), "hex")
          : Buffer.from(archivo);

    const total = fullBuf.length;
    const headers = event.headers || {};
    const range = headers.range || headers.Range;

    // Disposition
    const disp = qs.download ? `attachment; filename="${filename}"` : `inline; filename="${filename}"`;
    const ct   = mime_type || "video/mp4";

    if (range) {
      // Soporte byte-range (iOS/Android Safari/Chrome lo requieren)
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (!m) return { statusCode: 416, body: "Range inválido" };

      let start = m[1] ? parseInt(m[1], 10) : 0;
      let end   = m[2] ? parseInt(m[2], 10) : total - 1;
      if (isNaN(start) || start < 0) start = 0;
      if (isNaN(end) || end >= total) end = total - 1;
      if (start > end) return { statusCode: 416, body: "Range inválido" };

      const chunk = fullBuf.slice(start, end + 1);
      return {
        statusCode: 206,
        headers: {
          "Content-Type": ct,
          "Content-Disposition": disp,
          "Accept-Ranges": "bytes",
          "Content-Range": `bytes ${start}-${end}/${total}`,
          "Content-Length": String(chunk.length),
          "Cache-Control": "private, max-age=300"
        },
        isBase64Encoded: true,
        body: chunk.toString("base64")
      };
    }

    // Respuesta completa
    return {
      statusCode: 200,
      headers: {
        "Content-Type": ct,
        "Content-Disposition": disp,
        "Accept-Ranges": "bytes",
        "Content-Length": String(total),
        "Cache-Control": "private, max-age=300"
      },
      isBase64Encoded: true,
      body: fullBuf.toString("base64")
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
