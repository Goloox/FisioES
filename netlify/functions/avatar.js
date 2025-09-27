// netlify/functions/avatar.js  (ESM + handler nombrado + jwt en query)
import { Client } from "pg";
import jwt from "jsonwebtoken";

const { DATABASE_URL, JWT_SECRET } = process.env;

function getClaims(event) {
  const qs = event.queryStringParameters || {};
  const hdrs = event.headers || {};
  const headerAuth = hdrs.authorization || hdrs.Authorization || "";
  const queryJwt = qs.jwt;

  let token = null;
  if (headerAuth.startsWith("Bearer ")) token = headerAuth.slice("Bearer ".length).trim();
  else if (queryJwt) token = queryJwt;

  if (!token) throw new Error("No autorizado");
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

    if (!r.rowCount || !r.rows[0].imagen) {
      return { statusCode: 404, body: "No image" };
    }

    return {
      statusCode: 200,
      headers: {
        "Content-Type": "image/jpeg",
        "Cache-Control": "private, max-age=300"
      },
      body: Buffer.from(r.rows[0].imagen).toString("base64"),
      isBase64Encoded: true
    };
  } catch {
    return { statusCode: 401, body: "Unauthorized" };
  }
};
