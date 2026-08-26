import crypto from 'node:crypto';

const COOKIE_NAME = 'elitepath_staff_session';
const MAX_AGE = 60 * 60 * 8;

function getCookie(request, name) {
  const cookies = request.headers.cookie || '';
  const match = cookies.split(';').map(item => item.trim()).find(item => item.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
}
function sign(value) { return crypto.createHmac('sha256', process.env.ADMIN_SESSION_SECRET).update(value).digest('base64url'); }
function constantTimeMatch(provided, expected) {
  const left = Buffer.from(String(provided || '').trim()); const right = Buffer.from(String(expected || '').trim());
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
export function validCredentials(username, password) {
  return Boolean(process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) && constantTimeMatch(username, process.env.ADMIN_USERNAME) && constantTimeMatch(password, process.env.ADMIN_PASSWORD);
}
export function createSession() {
  const payload = Buffer.from(JSON.stringify({ expires: Math.floor(Date.now() / 1000) + MAX_AGE })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}
export function hasValidSession(request) {
  if (!process.env.ADMIN_SESSION_SECRET) return false;
  const token = getCookie(request, COOKIE_NAME);
  if (!token || !token.includes('.')) return false;
  const [payload, signature] = token.split('.'); const expected = sign(payload);
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()).expires > Math.floor(Date.now() / 1000); } catch { return false; }
}
export function setSessionCookie(response, token) { response.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${MAX_AGE}`); }
export function clearSessionCookie(response) { response.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`); }
