
// netlify/functions/cita_create.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }

  const fecha = body.fecha; // ISO string
  const titulo = (body.titulo || "").trim();
  const descripcion = (body.descripcion || "").trim();

  if (!fecha || !titulo) {
    return { statusCode: 400, body: "fecha y titulo son requeridos" };
  }

  const usuario_id = Number(claims.id || claims.user_id || claims.sub || claims.usuario_id);
  if (!usuario_id) return { statusCode: 400, body: "usuario no válido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const ins = await client.query(
      `INSERT INTO fisio.cita (fecha, titulo, descripcion, usuario_id, estado)
       VALUES ($1, $2, $3, $4, 3)
       RETURNING id_cita, fecha, titulo, descripcion, usuario_id, estado`,
      [fecha, titulo, descripcion || null, usuario_id]
    );

    return {
      statusCode: 201,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ ok:true, row:ins.rows[0] })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
