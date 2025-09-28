// netlify/functions/citas_list.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

/*
  Devuelve citas con imágenes.
  Soporta:
    - ?id_cliente=XX  -> JOIN agendar_cita (incluye estado)
    - ?id_usuario=YY  -> citas creadas por usuario (fallback)
  Paginación: ?page, ?pageSize
*/

export const handler = async (event) => {
  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth?.startsWith?.("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const role = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  const meId = Number(claims.id ?? claims.sub ?? claims.usuario_id ?? claims.user_id);

  const qs = event.queryStringParameters || {};
  const idCliente = qs.id_cliente ? Number(qs.id_cliente) : null;
  const idUsuario = qs.id_usuario ? Number(qs.id_usuario) : null;

  if (!idCliente && !idUsuario) {
    return { statusCode: 400, body: "id_cliente o id_usuario requerido" };
  }

  // Autorización básica: admin puede ver todo; no-admin solo lo suyo
  if (role !== 1) {
    if (idCliente && meId !== idCliente) return { statusCode: 403, body: "Prohibido" };
    if (idUsuario && meId !== idUsuario) return { statusCode: 403, body: "Prohibido" };
  }

  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "20", 10)));

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    let rows = [];
    let total = 0;

    if (idCliente) {
      // Citas del cliente con estado desde agendar_cita
      const totalRes = await client.query(
        `SELECT COUNT(*)::int c
           FROM fisio.agendar_cita ac
           JOIN fisio.cita c ON c.id_cita = ac.id_cita
          WHERE ac.id_cliente = $1`,
        [idCliente]
      );
      total = totalRes.rows[0].c;

      const rowsRes = await client.query(
        `SELECT c.id_cita,
                COALESCE(ac.fecha, c.fecha) AS fecha,
                c.titulo, c.descripcion,
                ac.estado,
                c.created_at, c.updated_at
           FROM fisio.agendar_cita ac
           JOIN fisio.cita c ON c.id_cita = ac.id_cita
          WHERE ac.id_cliente = $1
          ORDER BY fecha DESC
          LIMIT $2 OFFSET $3`,
        [idCliente, pageSize, (page-1)*pageSize]
      );
      rows = rowsRes.rows;
    } else {
      // Fallback: citas por usuario creador (sin estado)
      const totalRes = await client.query(
        `SELECT COUNT(*)::int c FROM fisio.cita WHERE usuario_id = $1`, [idUsuario]
      );
      total = totalRes.rows[0].c;

      const rowsRes = await client.query(
        `SELECT id_cita, fecha, titulo, descripcion, NULL::int AS estado, created_at, updated_at
           FROM fisio.cita
          WHERE usuario_id = $1
          ORDER BY fecha DESC
          LIMIT $2 OFFSET $3`,
        [idUsuario, pageSize, (page-1)*pageSize]
      );
      rows = rowsRes.rows;
    }

    // Imágenes por id_cita
    if (rows.length) {
      const ids = rows.map(r=>r.id_cita);
      const imgs = await client.query(
        `SELECT id, id_cita
           FROM fisio.imagenes_cita
          WHERE id_cita = ANY($1::bigint[])
          ORDER BY id`,
        [ids]
      );
      const byCita = {};
      imgs.rows.forEach(x=>{ (byCita[x.id_cita] ||= []).push(x.id); });
      rows.forEach(r=> r.images = byCita[r.id_cita] || []);
    }

    return {
      statusCode: 200,
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ rows, total, page, pageSize })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
