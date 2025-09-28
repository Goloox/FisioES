// netlify/functions/calendar_events.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  // auth admin
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth?.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };
  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }
  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const qs = event.queryStringParameters || {};
  const start = qs.start; // ISO
  const end   = qs.end;   // ISO
  if (!start || !end) return { statusCode: 400, body: "start/end requeridos" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const sql = `
      SELECT ac.id, ac.fecha, ac.estado,
             u.nombre_completo AS cliente, u.correo,
             c.titulo, c.descripcion
        FROM fisio.agendar_cita ac
        JOIN fisio.cita c   ON c.id_cita = ac.id_cita
        JOIN fisio.usuario u ON u.id     = ac.id_cliente
       WHERE ac.fecha >= $1 AND ac.fecha < $2
       ORDER BY ac.fecha ASC`;
    const r = await client.query(sql, [start, end]);
    // construir eventos (sin end -> FullCalendar usa una hora por defecto visual)
    const rows = r.rows.map(x => ({
      id: x.id,
      start: x.fecha,   // ISO de Postgres
      end: null,
      estado: x.estado,
      cliente: x.cliente,
      correo: x.correo,
      titulo: x.titulo,
      descripcion: x.descripcion
    }));
    return { statusCode: 200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ rows }) };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
