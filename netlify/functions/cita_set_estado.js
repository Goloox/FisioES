// netlify/functions/cita_set_estado.js
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
  const usuario_id = Number(claims.id || claims.user_id || claims.sub || claims.usuario_id);

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }

  const id_cita = Number(body.id_cita);
  const estado = Number(body.estado); // 1..5
  if (!id_cita || ![1,2,3,4,5].includes(estado))
    return { statusCode: 400, body: "Parámetros inválidos" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    // Si es cliente (no admin), solo puede modificar sus citas y a estados permitidos
    if (rol !== 1) {
      // permitir al cliente SOLO 2 (cancelar) o 4 (posponer)
      if (![2,4].includes(estado)) {
        return { statusCode: 403, body: "Acción no permitida para cliente" };
      }
      const owner = await client.query(
        `SELECT 1 FROM fisio.cita WHERE id_cita=$1 AND usuario_id=$2 LIMIT 1`,
        [id_cita, usuario_id]
      );
      if (!owner.rowCount) return { statusCode: 403, body: "No puedes modificar esta cita" };
    }

    const upd = await client.query(
      `UPDATE fisio.cita
          SET estado = $2,
              updated_at = (NOW() AT TIME ZONE 'UTC')
        WHERE id_cita = $1
      RETURNING id_cita, usuario_id, estado`,
      [id_cita, estado]
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
