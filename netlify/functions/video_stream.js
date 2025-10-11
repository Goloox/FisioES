// netlify/functions/video_stream.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

/* -------- utilidades -------- */
function getToken(event) {
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  if (q.jwt) return q.jwt;
  return null;
}

function getUserFromJwt(token) {
  const claims = jwt.verify(token, process.env.JWT_SECRET);
  // Acepta varias claves posibles
  const userId =
    claims.id ??
    claims.user_id ??
    claims.usuario_id ??
    claims.sub ??
    claims.uid;
  const rolId =
    claims.rol_id ??
    claims.role_id ??
    claims.role ??
    claims.rol;
  return { userId: Number(userId), rolId: Number(rolId) };
}

function sniffContentType(buf) {
  // MP4 / ISO BMFF: "ftyp" en bytes 4..7
  if (buf.length >= 12 && buf.toString("ascii", 4, 8) === "ftyp") {
    return "video/mp4";
  }
  // WebM: 1A 45 DF A3 (EBML)
  if (
    buf.length >= 4 &&
    buf[0] === 0x1a &&
    buf[1] === 0x45 &&
    buf[2] === 0xdf &&
    buf[3] === 0xa3
  ) {
    return "video/webm";
  }
  // Ogg: "OggS"
  if (buf.length >= 4 && buf.toString("ascii", 0, 4) === "OggS") {
    return "video/ogg";
  }
  return "video/mp4"; // por defecto
}

function cors(h = {}) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Range, Content-Type",
    ...h,
  };
}

/* -------- handler -------- */
export const handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: cors() };
  }

  const token = getToken(event);
  if (!token) return { statusCode: 401, headers: cors(), body: "Unauthorized" };

  let user;
  try {
    user = getUserFromJwt(token);
  } catch {
    return { statusCode: 401, headers: cors(), body: "Unauthorized" };
  }
  if (!user.userId) {
    return { statusCode: 401, headers: cors(), body: "Unauthorized" };
  }

  const id_video = Number((event.queryStringParameters || {}).id || 0);
  if (!id_video) {
    return { statusCode: 400, headers: cors(), body: "id requerido" };
  }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });

  await client.connect();
  try {
    // 1) Traer el video
    const vRes = await client.query(
      `SELECT v.id_video, v.titulo, v.video_url
         FROM fisio.video v
        WHERE v.id_video = $1
        LIMIT 1`,
      [id_video]
    );
    if (!vRes.rowCount) {
      return { statusCode: 404, headers: cors(), body: "No existe" };
    }
    const video = vRes.rows[0];

    // 2) Permisos: admin o asignado
    if (user.rolId !== 1) {
      const asRes = await client.query(
        `SELECT 1
           FROM fisio.video_asignacion
          WHERE id_usuario = $1 AND id_video = $2
          LIMIT 1`,
        [user.userId, id_video]
      );
      if (!asRes.rowCount) {
        return { statusCode: 403, headers: cors(), body: "Prohibido" };
      }
    }

    // 3) ¿Existe tabla fisio.video_archivo?
    const tabRes = await client.query(
      `SELECT to_regclass('fisio.video_archivo') AS t`
    );
    const hasArchivoTable = !!tabRes.rows?.[0]?.t;

    // 4) Si hay tabla, intentar leer binario
    if (hasArchivoTable) {
      let binRes;
      try {
        binRes = await client.query(
          `SELECT archivo
             FROM fisio.video_archivo
            WHERE id_video = $1
            LIMIT 1`,
          [id_video]
        );
      } catch (e) {
        // Si la tabla existe pero no tiene la columna "archivo" (muy raro),
        // devolvemos 500 con claridad.
        return {
          statusCode: 500,
          headers: cors(),
          body: "Error leyendo video_archivo: " + e.message,
        };
      }

      if (binRes.rowCount) {
        // Convertir a Buffer (por si llega con forma {type:'Buffer',data:[]})
        const raw = binRes.rows[0].archivo;
        const buf =
          Buffer.isBuffer(raw)
            ? raw
            : raw?.type === "Buffer" && Array.isArray(raw?.data)
            ? Buffer.from(raw.data)
            : typeof raw === "string" && raw.startsWith("\\x")
            ? Buffer.from(raw.slice(2), "hex")
            : Buffer.from(raw || []);

        const total = buf.length;
        const mime = sniffContentType(buf);
        const range = event.headers?.range || event.headers?.Range;

        // Streaming con Range
        if (range) {
          // Ejemplo: "bytes=0-"
          const match = /^bytes=(\d+)-(\d+)?$/.exec(range);
          if (!match) {
            return {
              statusCode: 416,
              headers: cors({
                "Content-Range": `bytes */${total}`,
              }),
              body: "",
            };
          }
          const start = parseInt(match[1], 10);
          const end = match[2] ? parseInt(match[2], 10) : total - 1;
          if (start >= total || end >= total || start > end) {
            return {
              statusCode: 416,
              headers: cors({
                "Content-Range": `bytes */${total}`,
              }),
              body: "",
            };
          }
          const chunk = buf.subarray(start, end + 1);
          return {
            statusCode: 206,
            headers: cors({
              "Content-Type": mime,
              "Content-Length": String(chunk.length),
              "Accept-Ranges": "bytes",
              "Content-Range": `bytes ${start}-${end}/${total}`,
              "Cache-Control": "private, max-age=0, no-store",
            }),
            isBase64Encoded: true,
            body: chunk.toString("base64"),
          };
        }

        // Respuesta completa
        return {
          statusCode: 200,
          headers: cors({
            "Content-Type": mime,
            "Content-Length": String(total),
            "Accept-Ranges": "bytes",
            "Cache-Control": "private, max-age=0, no-store",
          }),
          isBase64Encoded: true,
          body: buf.toString("base64"),
        };
      }
    }

    // 5) Sin binario → redirigir a video_url (debe ser URL válida o ruta servible)
    if (video.video_url) {
      return {
        statusCode: 302,
        headers: cors({ Location: video.video_url }),
        body: "",
      };
    }

    // Si tampoco hay URL, no hay cómo servirlo
    return {
      statusCode: 404,
      headers: cors(),
      body: "Video sin archivo ni URL",
    };
  } catch (e) {
    return { statusCode: 500, headers: cors(), body: "Error: " + e.message };
  } finally {
    try {
      await client.end();
    } catch {}
  }
};
