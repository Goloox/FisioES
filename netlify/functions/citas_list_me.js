// netlify/functions/citas_list_me.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const usuario_id = Number(claims.id || claims.user_id || claims.sub || claims.usuario_id);
  if (!usuario_id) return { statusCode: 400, body: "usuario no válido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const citasRes = await client.query(
      `SELECT id_cita, fecha, estado, titulo, descripcion
         FROM fisio.cita
        WHERE usuario_id = $1
        ORDER BY fecha DESC`,
      [usuario_id]
    );

    const ids = citasRes.rows.map(r => r.id_cita);
    let imagesByCita = new Map();
    if (ids.length) {
      const imgsRes = await client.query(
        `SELECT id, id_cita
           FROM fisio.imagenes_cita
          WHERE id_cita = ANY($1::bigint[])`,
        [ids]
      );
      for (const row of imgsRes.rows) {
        if (!imagesByCita.has(row.id_cita)) imagesByCita.set(row.id_cita, []);
        imagesByCita.get(row.id_cita).push(row.id);
      }
    }

    const rows = citasRes.rows.map(r => ({
      ...r,
      images: imagesByCita.get(r.id_cita) || []
    }));

    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ rows })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
