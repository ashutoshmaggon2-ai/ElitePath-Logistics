import { createSession, setSessionCookie, validCredentials } from './_auth.mjs';

export default function handler(request, response) {
  if (request.method !== 'POST') return response.status(405).json({ error: 'Method not allowed' });
  const missing = ['ADMIN_USERNAME', 'ADMIN_PASSWORD', 'ADMIN_SESSION_SECRET'].filter(name => !process.env[name]);
  if (missing.length) {
    return response.status(503).json({ error: `Login configuration is incomplete. Missing: ${missing.join(', ')}.` });
  }
  const { username, password } = request.body || {};
  if (!validCredentials(username, password)) return response.status(401).json({ error: 'Invalid username or password.' });
  setSessionCookie(response, createSession());
  return response.status(200).json({ authenticated: true });
}
