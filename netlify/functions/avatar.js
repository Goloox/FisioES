// netlify/functions/avatar.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

const { DATABASE_URL, JWT_SECRET } = process.env;

function getClaims(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) throw new Error("No autorizado");
  const token = auth.slice("Bearer ".length).trim();
  return jwt.verify(token, JWT_SECRET);
}

export const handler = async (event) => {
  try {
    const claims = getClaims(event);
    const qs = event.queryStringParameters || {};
    const claimId = claims.usuario_id ?? claims.user_id ?? claims.id;
    const isAdmin = (claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) === 1;

    let usuarioId = claimId;
    if (qs.me) {
      usuarioId = claimId;
    } else if (qs.usuario_id) {
      const requested = Number(qs.usuario_id);
      if (!isAdmin && requested !== claimId) {
        return { statusCode: 403, body: "Prohibido" };
      }
      usuarioId = requested;
    }

    if (!usuarioId) return { statusCode: 400, body: "usuario_id o ?me=1 requerido" };

    const client = new Client({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
    await client.connect();

    const r = await client.query(
      `SELECT imagen
         FROM fisio.imagen_usuario
        WHERE usuario_id = $1
        ORDER BY updated_at DESC NULLS LAST, id DESC
        LIMIT 1`,
      [usuarioId]
    );
    await client.end();

    if (!r.rowCount || !r.rows[0].imagen) {
      return { statusCode: 404, body: "No image" };
    }

    const buf = r.rows[0].imagen;
    // Detección simple del tipo
    let mime = "image/jpeg";
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) mime = "image/png";       // PNG
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) mime = "image/jpeg";                           // JPEG
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) mime = "image/gif";         // GIF
    // (si quieres más tipos, se agregan)

    return {
      statusCode: 200,
      headers: {
        "Content-Type": mime,
        "Cache-Control": "private, max-age=300"
      },
      body: Buffer.from(buf).toString("base64"),
      isBase64Encoded: true
    };
  } catch {
    return { statusCode: 401, body: "Unauthorized" };
  }
};
