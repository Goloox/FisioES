// netlify/functions/cita_upload_image.js
import { Client } from "pg";
import jwt from "jsonwebtoken";
import busboy from "busboy";

export const handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode:405, body:"Method Not Allowed" };

  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  if (!auth.startsWith("Bearer ")) return { statusCode: 401, body: "Unauthorized" };

  let claims;
  try { claims = jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return { statusCode: 401, body: "Unauthorized" }; }

  const rol = Number(claims.rol_id ?? claims.role_id ?? claims.role);
  if (rol !== 1) return { statusCode: 403, body: "Solo ADMIN" };

  // Parse multipart/form-data
  const bb = busboy({ headers: h });
  const parts = await new Promise((resolve, reject)=>{
    const out = { fields:{}, file:null };
    bb.on('file', (name, file, info)=>{
      const chunks = [];
      file.on('data', d=>chunks.push(d));
      file.on('end', ()=>{ out.file = Buffer.concat(chunks); });
    });
    bb.on('field', (name, val)=>{ out.fields[name] = val; });
    bb.on('error', reject);
    bb.on('close', ()=> resolve(out));
    bb.end(Buffer.from(event.body, event.isBase64Encoded ? 'base64' : 'utf8'));
  });

  const id_cita = Number(parts.fields.id_cita||0);
  if(!id_cita || !parts.file) return { statusCode:400, body:"id_cita y file requeridos" };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    // Confirmar cita existe
    const chk = await client.query(`SELECT 1 FROM fisio.cita WHERE id_cita=$1`, [id_cita]);
    if(!chk.rowCount) return { statusCode:404, body:"Cita no existe" };

    await client.query(
      `INSERT INTO fisio.imagenes_cita(id_cita, imagen, created_at)
       VALUES ($1, $2, NOW())`,
      [id_cita, parts.file]
    );
    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ ok:true }) };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
