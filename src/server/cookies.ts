export interface CookieOptions {
  path: string;
  maxAge: number;
  secure: boolean;
}

/** HttpOnly + SameSite=Lax: never readable by page scripts, still sent on the PDS's redirect back. */
export function serializeCookie(name: string, value: string, { path, maxAge, secure }: CookieOptions): string {
  return `${name}=${encodeURIComponent(value)}; Path=${path}; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

export function clearCookie(name: string, { path, secure }: Omit<CookieOptions, "maxAge">): string {
  return serializeCookie(name, "", { path, maxAge: 0, secure });
}

export function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie");
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      try {
        return decodeURIComponent(part.slice(eq + 1).trim());
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

export function appendSetCookie(response: Response, cookie: string): void {
  response.headers.append("set-cookie", cookie);
}
