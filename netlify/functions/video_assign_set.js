// netlify/functions/video_assign_set.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if (event.httpMethod !== "POST")
    return { statusCode: 405, body: "Method Not Allowed" };

  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }

  const id_usuario  = Number(body.id_usuario || 0);
  const id_video    = Number(body.id_video || 0);
  const observacion = (body.observacion || "").trim();
  const remove_id   = Number(body.remove_id || 0); // si se pasa, elimina

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  await client.connect();
  try {
    if (remove_id) {
      const del = await client.query(
        `DELETE FROM fisio.video_asignacion WHERE id=$1 RETURNING id`,
        [remove_id]
      );
      if (!del.rowCount) return { statusCode: 404, body: "No existe" };
      return { statusCode: 200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true, removed: del.rows[0] }) };
    }

    if (!id_usuario || !id_video) {
      return { statusCode: 400, body: "id_usuario e id_video requeridos" };
    }

    // upsert simple: si ya existe para ese usuario/video, solo actualiza observación y updated_at
    const up = await client.query(
      `INSERT INTO fisio.video_asignacion (id_usuario, id_video, observacion, created_at, updated_at)
       VALUES ($1,$2,$3, (now() at time zone 'UTC'), (now() at time zone 'UTC'))
       ON CONFLICT ON CONSTRAINT video_asignacion_pkey DO NOTHING
       RETURNING *`,
      [id_usuario, id_video, observacion || null]
    );

    if (up.rowCount) {
      return { statusCode: 200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true, row: up.rows[0] }) };
    }

    // Si no hay PK de conflicto, intentamos actualizar el más reciente de ese par
    const upd = await client.query(
      `UPDATE fisio.video_asignacion
          SET observacion = COALESCE($3, observacion),
              updated_at = (now() at time zone 'UTC')
        WHERE id_usuario = $1 AND id_video = $2
        RETURNING *`,
      [id_usuario, id_video, observacion || null]
    );

    return { statusCode: 200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true, row: upd.rows[0] || null }) };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
