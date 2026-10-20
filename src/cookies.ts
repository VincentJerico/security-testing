/** The cookie fields that decide how well a session cookie is protected. */
export interface CookieFlags {
  name: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None';
}

/**
 * Problems with a cookie that holds a session token. `Secure` is only required when the app is
 * served over HTTPS, because browsers drop Secure cookies on plain-HTTP localhost.
 */
export function checkSessionCookie(cookie: CookieFlags, { https = false } = {}): string[] {
  const problems: string[] = [];
  if (!cookie.httpOnly) problems.push(`${cookie.name} is readable by scripts (HttpOnly not set)`);
  if (cookie.sameSite === 'None')
    problems.push(`${cookie.name} is sent on cross-site requests (SameSite=None)`);
  if (https && !cookie.secure)
    problems.push(`${cookie.name} can be sent over plain HTTP (Secure not set)`);
  return problems;
}
