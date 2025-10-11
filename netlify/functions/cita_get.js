// netlify/functions/cita_get.js
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

  const id = Number((event.queryStringParameters||{}).id || 0);
  if(!id) return { statusCode:400, body:"id requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const rowRes = await client.query(
      `SELECT c.id_cita, c.fecha, c.titulo, c.descripcion, c.estado,
              u.id as usuario_id, u.nombre_completo, u.correo
         FROM fisio.cita c
         JOIN fisio.usuario u ON u.id = c.usuario_id
        WHERE c.id_cita = $1
        LIMIT 1`, [id]
    );
    if(!rowRes.rowCount) return { statusCode:404, body:"No existe" };

    const imgsRes = await client.query(
      `SELECT id FROM fisio.imagenes_cita WHERE id_cita=$1 ORDER BY id DESC`, [id]
    );

    return {
      statusCode:200,
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ row: rowRes.rows[0], images: imgsRes.rows })
    };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
