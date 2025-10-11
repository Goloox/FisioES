import jwt from "jsonwebtoken";

export function readToken(event) {
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  if (ah?.startsWith?.("Bearer ")) return ah.slice(7);
  if (q.jwt) return q.jwt;
  return null;
}

export function requireUserClaims(event) {
  const token = readToken(event);
  if (!token) return { ok:false, statusCode:401, error:"Unauthorized" };
  try {
    const claims = jwt.verify(token, process.env.JWT_SECRET);
    const user_id = Number(claims.id ?? claims.user_id ?? claims.usuario_id ?? claims.sub);
    const rol_id  = Number(claims.rol_id ?? claims.role_id ?? claims.role ?? claims.rol);
    if (!user_id) return { ok:false, statusCode:401, error:"Unauthorized" };
    return { ok:true, claims:{ user_id, rol_id, raw:claims } };
  } catch {
    return { ok:false, statusCode:401, error:"Unauthorized" };
  }
}
