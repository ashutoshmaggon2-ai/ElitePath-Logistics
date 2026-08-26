import { createSession, setSessionCookie, validCredentials } from './_auth.mjs';

export default function handler(request, response) {
  if (request.method !== 'POST') return response.status(405).json({ error: 'Method not allowed' });
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD || !process.env.ADMIN_SESSION_SECRET) {
    return response.status(503).json({ error: 'Login configuration is incomplete. Check the Vercel environment variables for this deployment.' });
  }
  const { username, password } = request.body || {};
  if (!validCredentials(username, password)) return response.status(401).json({ error: 'Invalid username or password.' });
  setSessionCookie(response, createSession());
  return response.status(200).json({ authenticated: true });
}
