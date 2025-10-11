import { Client } from "pg";
import { requireUserClaims } from "./_auth.js";

async function firstOk(client, sqls, params){
  let last=null;
  for(const s of sqls){
    try{ return await client.query(s, params); }
    catch(e){ if(!/relation .* does not exist/i.test(e.message)) throw e; last=e; }
  }
  throw last || new Error("No query worked");
}

export const handler = async (event) => {
  const auth = requireUserClaims(event);
  if(!auth.ok) return { statusCode:auth.statusCode, body:auth.error };
  const { user_id } = auth.claims;

  const client = new Client({ connectionString:process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();
  try{
    const r = await firstOk(client, [
      `SELECT va.id, va.id_video, va.id_usuario, va.observacion, va.created_at, va.updated_at,
              v.titulo, v.objetivo
         FROM fisio.video_asignacions va
         JOIN fisio.video v ON v.id_video = va.id_video
        WHERE va.id_usuario = $1
        ORDER BY COALESCE(va.updated_at, va.created_at) DESC, va.id DESC`,
      `SELECT va.id, va.id_video, va.id_usuario, va.observacion, va.created_at, va.updated_at,
              v.titulo, v.objetivo
         FROM fisio.video_asignacion va
         JOIN fisio.video v ON v.id_video = va.id_video
        WHERE va.id_usuario = $1
        ORDER BY COALESCE(va.updated_at, va.created_at) DESC, va.id DESC`,
    ], [user_id]);

    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body:JSON.stringify({ rows:r.rows }) };
  }catch(e){
    return { statusCode:500, body:"Error: "+e.message };
  }finally{ try{ await client.end(); }catch{} }
};
