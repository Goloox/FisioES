import jwt from "jsonwebtoken";
export const handler = async (event) => {
  const h = event.headers || {};
  const q = event.queryStringParameters || {};
  const ah = h.authorization || h.Authorization || "";
  const token = ah?.startsWith?.("Bearer ") ? ah.slice(7) : (q.jwt || "");
  if(!token) return { statusCode:401, body:"No token" };
  try{
    const claims = jwt.verify(token, process.env.JWT_SECRET);
    return { statusCode:200, headers:{ "Content-Type":"application/json" }, body:JSON.stringify({ ok:true, claims }) };
  }catch(e){
    return { statusCode:401, body:"Unauthorized: "+e.message };
  }
};
