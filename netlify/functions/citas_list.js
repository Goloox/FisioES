// netlify/functions/citas_list.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  const hdr = event.headers || {};
  const auth = hdr.authorization || hdr.Authorization || "";
  if (!auth?.startsWith?.("Bearer ")) return { statusCode: 401, body: "Unauthorized" };
  let claims; try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); } catch { return { statusCode: 401, body: "Unauthorized" }; }

  const role = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
  const qs = event.queryStringParameters || {};
  const idUsuario = Number(qs.id_usuario || qs.usuario_id || 0);
  if (!idUsuario) return { statusCode: 400, body: "id_usuario requerido" };
  if (role !== 1 && Number(claims.id ?? claims.sub ?? claims.usuario_id) !== idUsuario) {
    return { statusCode: 403, body: "Prohibido" };
  }

  const page = Math.max(1, parseInt(qs.page || "1", 10));
  const pageSize = Math.min(100, Math.max(1, parseInt(qs.pageSize || "20", 10)));

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try {
    const totalRes = await client.query(`SELECT COUNT(*)::int c FROM fisio.cita WHERE usuario_id=$1`, [idUsuario]);
    const total = totalRes.rows[0].c;

    const rowsRes = await client.query(
      `SELECT id_cita, fecha, titulo, descripcion, created_at, updated_at
         FROM fisio.cita
        WHERE usuario_id=$1
        ORDER BY fecha DESC
        LIMIT $2 OFFSET $3`,
      [idUsuario, pageSize, (page-1)*pageSize]
    );
    const rows = rowsRes.rows;

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
      imgs.rows.forEach(x=>{
        (byCita[x.id_cita] ||= []).push(x.id);
      });
      rows.forEach(r=> r.images = byCita[r.id_cita] || []);
    }

    return {
      statusCode: 200,
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ rows, total, page, pageSize })
    };
  } catch (e) {
    return { statusCode: 500, body: "Error: " + e.message };
  } finally { try{ await client.end(); }catch{} }
};
