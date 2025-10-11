// netlify/functions/cita_delete.js
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
  const userId = Number(claims.id ?? claims.user_id ?? claims.sub);

  let body;
  try { body = JSON.parse(event.body || "{}"); } catch { body = {}; }

  const id_cita = Number(body.id_cita || 0);
  if (!id_cita) return { statusCode: 400, body: "id_cita requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();

  try {
    // 1) Traer la cita para validar ownership/rol
    const cRes = await client.query(
      `SELECT id_cita, usuario_id, estado FROM fisio.cita WHERE id_cita=$1 LIMIT 1`,
      [id_cita]
    );
    if (!cRes.rowCount) return { statusCode: 404, body: "Cita no existe" };

    const cita = cRes.rows[0];

    // Si no es admin, debe ser dueño
    if (rol !== 1 && Number(cita.usuario_id) !== Number(userId)) {
      return { statusCode: 403, body: "No autorizado" };
    }

    // (Opcional) Política: bloquear si finalizada
    // if (Number(cita.estado) === 5 && rol !== 1) {
    //   return { statusCode: 400, body: "No se puede eliminar una cita finalizada" };
    // }

    await client.query('BEGIN');

    // 2) Borrar imágenes asociadas (si tuvieras FK on delete cascade no haría falta)
    await client.query(`DELETE FROM fisio.imagenes_cita WHERE id_cita=$1`, [id_cita]);

    // 3) Borrar la cita
    const del = await client.query(`DELETE FROM fisio.cita WHERE id_cita=$1`, [id_cita]);
    if (del.rowCount === 0) {
      await client.query('ROLLBACK');
      return { statusCode: 404, body: "No se pudo eliminar (no encontrada)" };
    }

    await client.query('COMMIT');

    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ ok:true, id_cita })
    };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
