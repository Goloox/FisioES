// netlify/functions/video_list.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  try {
    const hdr = event.headers || {};
    const auth = hdr.authorization || hdr.Authorization || "";
    if (!auth.startsWith("Bearer ")) {
      return { statusCode: 401, body: "Unauthorized" };
    }
    let claims;
    try {
      claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    } catch {
      return { statusCode: 401, body: "Unauthorized" };
    }
    // Solo ADMIN
    if (Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol) !== 1) {
      return { statusCode: 403, body: "Solo ADMIN" };
    }

    const qs = event.queryStringParameters || {};
    const page = Math.max(1, parseInt(qs.page || "1", 10));
    const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "10", 10)));
    const q = (qs.q || "").trim().toLowerCase();

    const args = [];
    const where = [];
    if (q) {
      args.push("%" + q + "%");
      // Reutilizamos el mismo parámetro en ambos LIKE (válido en PG)
      where.push(`(LOWER(titulo) LIKE $${args.length} OR LOWER(objetivo) LIKE $${args.length})`);
    }
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";

    const client = new Client({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
    await client.connect();
    try {
      // Garantiza la tabla de archivos (evita 500 antes del primer upload)
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

      const tot = await client.query(`SELECT COUNT(*)::int AS c FROM fisio.video ${whereSql}`, args);

      args.push(pageSize, (page - 1) * pageSize);
      const { rows } = await client.query(
        `SELECT v.id_video, v.objetivo, v.titulo, v.created_at,
                CASE WHEN va.id_video IS NULL THEN 0 ELSE 1 END AS has_file
           FROM fisio.video v
           LEFT JOIN fisio.video_archivo va ON va.id_video = v.id_video
          ${whereSql}
          ORDER BY v.id_video DESC
          LIMIT $${args.length - 1} OFFSET $${args.length}`,
        args
      );

      return {
        statusCode: 200,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rows, total: tot.rows[0].c, page, pageSize })
      };
    } finally {
      try { await client.end(); } catch {}
    }
  } catch (e) {
    return {
      statusCode: 500,
      headers: { "Content-Type": "text/plain" },
      body: "Error video_list: " + e.message
    };
  }
};
