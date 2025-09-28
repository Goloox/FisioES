// netlify/functions/agendar_set_estado.js
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

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }

  const id_agendar = Number(body.id_agendar);
  const estado = Number(body.estado); // 2=aceptado, 3=cancelado
  if (!id_agendar || ![2,3].includes(estado))
    return { statusCode: 400, body: "Parámetros inválidos" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const upd = await client.query(
      `UPDATE fisio.agendar_cita
          SET estado = $2, updated_at = (NOW() AT TIME ZONE 'UTC')
        WHERE id = $1
      RETURNING id, id_cliente, id_cita, estado`,
      [id_agendar, estado]
    );
    if (upd.rowCount === 0) return { statusCode: 404, body: "No existe" };
    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ ok:true, row: upd.rows[0] })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
