// netlify/functions/cita_delete_image.js
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
  const id = Number(body.id||0);
  if(!id) return { statusCode:400, body:"id requerido" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const del = await client.query(`DELETE FROM fisio.imagenes_cita WHERE id=$1`, [id]);
    if(!del.rowCount) return { statusCode:404, body:"No existe" };
    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true }) };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
