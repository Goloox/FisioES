// netlify/functions/cita_list_admin.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  const qs = event.queryStringParameters || {};
  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "10", 10)));

  const q = (qs.q || '').trim();
  const estados = (qs.estados || '').trim();  // "1,3,5"
  const onlyFuture = (qs.only_future || '1') === '1';

  // fechas YYYY-MM-DD
  const from = (qs.from || '').trim();
  const to   = (qs.to   || '').trim();

  const wh = [];
  const params = [];
  let idx = 1;

  // Filtros
  if (q) {
    wh.push(`(u.nombre_completo ILIKE $${idx} OR u.correo ILIKE $${idx} OR c.titulo ILIKE $${idx})`);
    params.push(`%${q}%`); idx++;
  }

  if (estados) {
    // limpiar valores a enteros válidos
    const arr = estados.split(',').map(x=>parseInt(x,10)).filter(n=>[1,2,3,4,5].includes(n));
    if (arr.length) {
      wh.push(`c.estado = ANY($${idx}::int[])`);
      params.push(arr); idx++;
    }
  } else {
    // por defecto, solo Aceptado
    wh.push(`c.estado = 1`);
  }

  if (onlyFuture) {
    wh.push(`c.fecha >= (CURRENT_DATE)`);
  } else {
    if (from) {
      wh.push(`c.fecha >= $${idx}::date`); params.push(from); idx++;
    }
    if (to) {
      wh.push(`c.fecha < ($${idx}::date + INTERVAL '1 day')`); params.push(to); idx++;
    }
  }

  const where = wh.length ? `WHERE ${wh.join(' AND ')}` : '';

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const totalRes = await client.query(
      `SELECT COUNT(*)::int c
         FROM fisio.cita c
         JOIN fisio.usuario u ON u.id = c.usuario_id
        ${where}`, params
    );
    const total = totalRes.rows[0].c;

    const rowsRes = await client.query(
      `SELECT c.id_cita, c.fecha, c.titulo, c.descripcion, c.estado,
              u.nombre_completo, u.correo
         FROM fisio.cita c
         JOIN fisio.usuario u ON u.id = c.usuario_id
        ${where}
        ORDER BY c.fecha ASC
        LIMIT $${idx} OFFSET $${idx+1}`,
      [...params, pageSize, (page-1)*pageSize]
    );

    return {
      statusCode: 200,
      headers: { "Content-Type":"application/json" },
      body: JSON.stringify({ rows: rowsRes.rows, total, page, pageSize })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally {
    try { await client.end(); } catch {}
  }
};
