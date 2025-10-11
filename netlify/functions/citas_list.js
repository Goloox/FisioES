// netlify/functions/citas_list.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const qs = event.queryStringParameters || {};
  const id_cliente = Number(qs.id_cliente || qs.id_usuario || 0);
  if (!id_cliente) return { statusCode: 400, body: "id_cliente requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    // Citas del usuario
    const citasRes = await client.query(
      `SELECT id_cita, fecha, estado, titulo, descripcion
         FROM fisio.cita
        WHERE usuario_id = $1
        ORDER BY fecha DESC`,
      [id_cliente]
    );

    // Si manejas imágenes en una tabla separada (id_cita -> ids)
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
