import jwt from "jsonwebtoken";

export function readToken(event){
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  if (q.jwt) return q.jwt;
  return null;
}

export function requireUserClaims(event){
  const token = readToken(event);
  if(!token) return { ok:false, statusCode:401, error:"Unauthorized" };
  try{
    const c = jwt.verify(token, process.env.JWT_SECRET);
    const user_id = Number(c.id ?? c.user_id ?? c.usuario_id ?? c.sub);
    const rol_id  = Number(c.rol_id ?? c.role_id ?? c.role ?? c.rol ?? 0);
    if(!user_id) return { ok:false, statusCode:401, error:"Unauthorized" };
    return { ok:true, claims:{ user_id, rol_id, raw:c } };
  }catch(e){
    return { ok:false, statusCode:401, error:"Unauthorized" };
  }
}
