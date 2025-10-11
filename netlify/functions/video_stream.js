import { Client } from "pg";
import { requireUserClaims, readToken } from "./_auth.js";

function sniff(buf){
  if (!buf || buf.length < 4) return "application/octet-stream";
  if (buf[0]===0x00 && buf[1]===0x00 && buf[2]===0x00 && buf[3]===0x20) return "video/mp4";
  return "application/octet-stream";
}

async function trySelectFile(client, id_video){
  // 1º plural (video_archivos), 2º singular (video_archivo)
  const variants = [
    `SELECT archivo, content_type FROM fisio.video_archivos WHERE id_video=$1 ORDER BY created_at DESC LIMIT 1`,
    `SELECT archivo, content_type FROM fisio.video_archivo  WHERE id_video=$1 ORDER BY created_at DESC LIMIT 1`,
  ];
  for (const sql of variants) {
    try {
      const r = await client.query(sql, [id_video]);
      if (r.rowCount) return r.rows[0];
    } catch (e) {
      if (!/relation .* does not exist/i.test(e.message)) throw e;
      // si no existe esa relación, probamos el siguiente variant
    }
  }
  return null;
}

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
    // ¿hay archivo subido?
    const fileRow = await trySelectFile(client, id_video);
    if (fileRow) {
      const raw = fileRow.archivo;
      const buf = Buffer.isBuffer(raw)
        ? raw
        : (raw?.type === "Buffer" && Array.isArray(raw?.data))
          ? Buffer.from(raw.data)
          : (typeof raw === "string" && raw.startsWith("\\x"))
            ? Buffer.from(raw.slice(2), "hex")
            : Buffer.from(raw);
      const ct = fileRow.content_type || sniff(buf);
      return {
        statusCode: 200,
        headers: {
          "Content-Type": ct,
          "Cache-Control":"private, max-age=300",
          "Content-Disposition":"inline"
        },
        isBase64Encoded: true,
        body: buf.toString("base64")
      };
    }

    // si no hay archivo, usamos la URL guardada en fisio.video
    const rv = await client.query(
      `SELECT video_url FROM fisio.video WHERE id_video=$1 LIMIT 1`,
      [id_video]
    );
    if (!rv.rowCount) return { statusCode: 404, body: "No existe el video" };

    const url = String(rv.rows[0].video_url || "").trim();
    if (!url) return { statusCode: 404, body: "Video sin archivo ni URL" };

    // si es URL absoluta http(s), redirigimos
    if (/^https?:\/\//i.test(url)) {
      return { statusCode: 302, headers: { Location: url } };
    }

    // path relativo -> añadimos jwt para que funciones internas autoricen
    const token = readToken(event) || "";
    const sep = url.includes("?") ? "&" : "?";
    return { statusCode: 302, headers: { Location: `${url}${sep}jwt=${encodeURIComponent(token)}` } };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
