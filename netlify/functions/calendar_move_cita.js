// netlify/functions/calendar_move_cita.js
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
  let   fecha   = (body.fecha||'').trim(); // "YYYY-MM-DD HH:MM:SS" (local)

  if(!id_cita || !fecha) return { statusCode:400, body:"id_cita y fecha requeridos" };

  // Forzar :00
  try{
    const d = new Date(fecha.replace('T',' ').replace('Z',''));
    d.setMinutes(0,0,0);
    const pad = n=> n<10?'0'+n:n;
    fecha = d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':00:00';
  }catch{ return { statusCode:400, body:"fecha inválida" }; }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const upd = await client.query(
      `UPDATE fisio.cita
          SET fecha=$2, updated_at=NOW()
        WHERE id_cita=$1`,
      [id_cita, fecha]
    );
    if(!upd.rowCount) return { statusCode:404, body:"No existe" };
    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true }) };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
