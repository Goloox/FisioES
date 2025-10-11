// netlify/functions/video_stream.js
import { Client } from "pg";
import { requireUserClaims, readToken } from "./_auth.js";

/*
 Sirve el binario desde fisio.video_archivo (si existe) o,
 si no hay archivo, redirige a v.video_url (si empieza con http/https).
 Requiere estar logueado: acepta Authorization: Bearer ... o ?jwt=...
*/
export const handler = async (event) => {
  const auth = requireUserClaims(event);
  if (!auth.ok) return { statusCode: auth.statusCode, body: auth.error };

  const qs = event.queryStringParameters || {};
  const id_video = Number(qs.id || qs.id_video || 0);
  if (!id_video) return { statusCode: 400, body: "id requerido" };

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await client.connect();
  try {
    // 1) ¿Hay archivo subido para el video?
    const r1 = await client.query(
      `SELECT archivo, content_type
         FROM fisio.video_archivo
        WHERE id_video = $1
        ORDER BY created_at DESC
        LIMIT 1`,
      [id_video]
    );

    if (r1.rowCount) {
      // normalizamos buffer
      const raw = r1.rows[0].archivo;
      const buf = Buffer.isBuffer(raw)
        ? raw
        : (raw?.type === "Buffer" && Array.isArray(raw?.data))
          ? Buffer.from(raw.data)
          : typeof raw === "string" && raw.startsWith("\\x")
            ? Buffer.from(raw.slice(2), "hex")
            : Buffer.from(raw);

      const ct = r1.rows[0].content_type || "application/octet-stream";
      return {
        statusCode: 200,
        headers: {
          "Content-Type": ct,
          "Cache-Control": "private, max-age=300",
          // evita downloads forzados: que el navegador lo intente reproducir
          "Content-Disposition":"inline"
        },
        isBase64Encoded: true,
        body: buf.toString("base64")
      };
    }

    // 2) Si no hay archivo, usamos la URL del video
    const r2 = await client.query(
      `SELECT video_url FROM fisio.video WHERE id_video = $1 LIMIT 1`,
      [id_video]
    );
    if (!r2.rowCount) return { statusCode: 404, body: "No existe el video" };

    const url = String(r2.rows[0].video_url || "").trim();
    if (/^https?:\/\//i.test(url)) {
      // redirigimos al recurso externo
      return {
        statusCode: 302,
        headers: { Location: url }
      };
    }

    // Si la URL almacenada es un path relativo a tu app, añade el JWT para autorización
    if (url) {
      const token = readToken(event);
      const sep = url.includes("?") ? "&" : "?";
      return {
        statusCode: 302,
        headers: { Location: `${url}${sep}jwt=${encodeURIComponent(token||"")}` }
      };
    }

    return { statusCode: 404, body: "Video sin archivo ni URL" };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
