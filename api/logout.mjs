import { clearSessionCookie } from './_auth.mjs';

export default function handler(request, response) {
  if (request.method !== 'POST') return response.status(405).json({ error: 'Method not allowed' });
  clearSessionCookie(response);
  return response.status(200).json({ authenticated: false });
}
