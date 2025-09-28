// netlify/functions/video_upload.js
import { Client } from "pg";
import jwt from "jsonwebtoken";
import Busboy from "busboy";

const MAX_MB = Number(process.env.MAX_VIDEO_MB || 10); // ajusta según hosting

function getAuthClaims(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return null;
  try { return jwt.verify(auth.slice(7), process.env.JWT_SECRET); } catch { return null; }
}

function parseMultipart(event) {
  return new Promise((resolve, reject) => {
    const headers = event.headers || {};
    const contentType = headers["content-type"] || headers["Content-Type"];
    if (!contentType) return reject(new Error("Content-Type faltante"));

    const bb = Busboy({ headers: { "content-type": contentType } });

    const fields = {};
    let fileBuf = null;
    let fileInfo = { filename: "", mime: "", size: 0 };

    bb.on("file", (name, stream, info) => {
      const { filename, mimeType } = info;
      fileInfo.filename = filename || "video.bin";
      fileInfo.mime = mimeType || "application/octet-stream";
      const chunks = [];
      let total = 0;

      stream.on("data", (c) => {
        total += c.length;
        if (total > MAX_MB * 1024 * 1024) {
          stream.unpipe(); stream.resume();
          reject(new Error(`El archivo excede ${MAX_MB}MB`));
          return;
        }
        chunks.push(c);
      });
      stream.on("end", () => {
        fileBuf = Buffer.concat(chunks);
        fileInfo.size = total;
      });
    });

    bb.on("field", (name, val) => { fields[name] = val; });
    bb.on("error", reject);
    bb.on("finish", () => resolve({ fields, fileBuf, fileInfo }));

    const body = event.isBase64Encoded ? Buffer.from(event.body || "", "base64") : Buffer.from(event.body || "");
    bb.end(body);
  });
}

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Method not allowed" }) };
  }

  const claims = getAuthClaims(event);
  if (!claims) return { statusCode: 401, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Unauthorized" }) };
  const role = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  if (role !== 1) return { statusCode: 403, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Solo ADMIN" }) };

  let parsed;
  try { parsed = await parseMultipart(event); }
  catch (e) {
    return { statusCode: 400, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Upload error: " + e.message }) };
  }

  const { fields, fileBuf, fileInfo } = parsed;
  const objetivo = (fields.objetivo || "").trim();
  const titulo   = (fields.titulo || "").trim();
  if (!objetivo || !titulo || !fileBuf) {
    return { statusCode: 400, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Faltan campos (objetivo, titulo, file)" }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS fisio.video_archivo(
        id BIGSERIAL PRIMARY KEY,
        id_video BIGINT NOT NULL UNIQUE REFERENCES fisio.video(id_video) ON DELETE CASCADE,
        filename VARCHAR(300) NOT NULL,
        mime_type VARCHAR(150) NOT NULL,
        size_bytes BIGINT NOT NULL,
        archivo BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    const v = await client.query(
      `INSERT INTO fisio.video (objetivo, titulo, video_url, created_at, updated_at)
       VALUES ($1,$2,NULL, now(), now())
       RETURNING id_video, objetivo, titulo, created_at, updated_at`,
      [objetivo, titulo]
    );
    const video = v.rows[0];

    await client.query(
      `INSERT INTO fisio.video_archivo (id_video, filename, mime_type, size_bytes, archivo)
       VALUES ($1,$2,$3,$4,$5)`,
      [video.id_video, fileInfo.filename, fileInfo.mime, fileInfo.size, fileBuf]
    );

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...video,
        filename: fileInfo.filename,
        mime_type: fileInfo.mime,
        size_bytes: fileInfo.size,
        stream_url: `/.netlify/functions/video_stream?id=${video.id_video}`
      })
    };
  } catch (e) {
    return { statusCode: 500, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ error: "Error: " + e.message }) };
  } finally {
    try { await client.end(); } catch {}
  }
};
