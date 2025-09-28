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
    const disp = qs.download ? `attachment; filename="${filename}"` : `inline; filename="${filename}"`;

    const buf = Buffer.isBuffer(archivo)
      ? archivo
      : (archivo?.type === "Buffer" && Array.isArray(archivo?.data))
        ? Buffer.from(archivo.data)
        : typeof archivo === "string" && archivo.startsWith("\\x")
          ? Buffer.from(archivo.slice(2), "hex")
          : Buffer.from(archivo);

    return {
      statusCode: 200,
      headers: {
        "Content-Type": mime_type || "video/mp4",
        "Content-Disposition": disp,
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
