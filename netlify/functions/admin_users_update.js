// netlify/functions/admin_users_update.js
const { Client } = require('pg');
const jwt = require('jsonwebtoken');

function getPayload(authHeader){
  if(!authHeader) return null;
  const [,token] = authHeader.split(' ');
  if(!token) return null;
  try{ return jwt.verify(token, process.env.JWT_SECRET); }catch{ return null; }
}

exports.handler = async (event)=>{
  if(event.httpMethod !== 'POST'){
    return { statusCode:405, body:'Method not allowed' };
  }
  const p = getPayload(event.headers.authorization);
  if(!p) return { statusCode:401, body:'Token inválido' };
  const rolId = p.rol_id ?? p.role_id ?? p.role ?? null;
  if(rolId !== 1) return { statusCode:403, body:'Solo ADMIN' };

  const body = JSON.parse(event.body||'{}');
  const { action, usuario_id, rol_id } = body;
  if(!action || !usuario_id) return { statusCode:400, body: JSON.stringify({error:'Parámetros inválidos'}) };

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl:{rejectUnauthorized:false} });
  await client.connect();

  try{
    if(action === 'toggle_active'){
      // lee estado actual
      const cur = await client.query('SELECT activo, rol_id FROM fisio.usuario WHERE id=$1',[usuario_id]);
      if(!cur.rowCount) return { statusCode:404, body: JSON.stringify({error:'Usuario no existe'}) };
      const actual = Number(cur.rows[0].activo);
      const nuevo = actual===1 ? 2 : 1;

      try{
        await client.query('UPDATE fisio.usuario SET activo=$1, updated_at=now() WHERE id=$2',[nuevo, usuario_id]);
      }catch(e){
        // Si viola trigger de “ADMIN no puede estar inactivo”
        return { statusCode:400, body: JSON.stringify({error: e.message}) };
      }
      return { statusCode:200, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ok:true, activo:nuevo}) };
    }

    if(action === 'set_role'){
      if(!rol_id) return { statusCode:400, body: JSON.stringify({error:'rol_id requerido'}) };
      // Primero activar si viene de ADMIN inactivo (para evitar conflictos)
      try{
        await client.query('UPDATE fisio.usuario SET rol_id=$1, updated_at=now() WHERE id=$2',[rol_id, usuario_id]);
      }catch(e){
        return { statusCode:400, body: JSON.stringify({error:e.message}) };
      }
      return { statusCode:200, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ok:true, rol_id}) };
    }

    return { statusCode:400, body: JSON.stringify({error:'Acción no soportada'}) };
  }catch(e){
    return { statusCode:500, body:'Error: '+e.message };
  }finally{
    try{ await client.end(); }catch{}
  }
};
