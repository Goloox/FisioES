// netlify/functions/video_create.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method not allowed" };
  }

  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };
  let claims;
  try {
    claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
  } catch {
    return { statusCode: 401, body: "Unauthorized" };
  }
  if (Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) !== 1) {
    return { statusCode: 403, body: "Solo ADMIN" };
  }

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }
  const { objetivo, titulo, video_url } = body;

  if (!objetivo || !titulo || !video_url) {
    return { statusCode: 400, body: "Faltan campos: objetivo, titulo, video_url" };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    const { rows } = await client.query(
      `INSERT INTO fisio.video (objetivo, titulo, video_url, created_at, updated_at)
       VALUES ($1,$2,$3, now(), now())
       RETURNING id_video, objetivo, titulo, video_url, created_at, updated_at`,
      [objetivo, titulo, video_url]
    );
    return { statusCode: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify(rows[0]) };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
