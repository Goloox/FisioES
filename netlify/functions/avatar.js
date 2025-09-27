// netlify/functions/avatar.js  (ESM)
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

export default async function handler(event) {
  try {
    const claims = getClaims(event);
    const qs = event.queryStringParameters || {};

    // Determina a quién se le va a servir el avatar
    const claimId = claims.usuario_id ?? claims.user_id ?? claims.id;
    let usuarioId = claimId;

    if (qs.me) {
      usuarioId = claimId;
    } else if (qs.usuario_id) {
      const requested = Number(qs.usuario_id);
      const isAdmin = (claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) === 1;
      // Solo ADMIN puede pedir la foto de otro; un no-admin solo la suya
      if (!isAdmin && requested !== claimId) {
        return { statusCode: 403, body: "Prohibido" };
      }
      usuarioId = requested;
    }

    if (!usuarioId) {
      return { statusCode: 400, body: "usuario_id o ?me=1 requerido" };
    }

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

    if (r.rowCount === 0 || !r.rows[0].imagen) {
      return { statusCode: 404, body: "No image" };
    }

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "image/jpeg",          // si luego agregas mime_type, cámbialo dinámico
        "Cache-Control": "private, max-age=300" // un poco de caché
      },
      body: Buffer.from(r.rows[0].imagen).toString("base64"),
      isBase64Encoded: true,
    };
  } catch {
    return { statusCode: 401, body: "Unauthorized" };
  }
}
