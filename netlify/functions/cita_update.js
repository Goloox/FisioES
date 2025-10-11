// netlify/functions/cita_update.js
import { Client } from "pg";
import jwt from "jsonwebtoken";

export const handler = async (event) => {
  if(event.httpMethod!=="POST") return { statusCode:405, body:"Method Not Allowed" };

  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  let body; try{ body = JSON.parse(event.body||"{}"); }catch{ body={}; }
  const id_cita = Number(body.id_cita||0);
  const titulo = (body.titulo||"").trim();
  const descripcion = (body.descripcion||"").trim();
  const estado = Number(body.estado||1);
  const fecha = (body.fecha||"").trim(); // "YYYY-MM-DD HH:00:00"

  if(!id_cita || !titulo || !fecha || ![1,2,3,4,5].includes(estado))
    return { statusCode:400, body:"Parámetros inválidos" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const upd = await client.query(
      `UPDATE fisio.cita
          SET titulo=$2, descripcion=$3, estado=$4, fecha=$5, updated_at=(NOW())
        WHERE id_cita=$1
      RETURNING id_cita`,
      [id_cita, titulo, descripcion, estado, fecha]
    );
    if(!upd.rowCount) return { statusCode:404, body:"No existe" };
    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true }) };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
