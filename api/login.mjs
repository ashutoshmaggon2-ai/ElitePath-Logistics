import { createSession, setSessionCookie, validCredentials } from './_auth.mjs';

export default function handler(request, response) {
  if (request.method !== 'POST') return response.status(405).json({ error: 'Method not allowed' });
  const { username, password } = request.body || {};
  if (!validCredentials(username, password)) return response.status(401).json({ error: 'Invalid username or password.' });
  setSessionCookie(response, createSession());
  return response.status(200).json({ authenticated: true });
}
