// src/modules/auth/utils/cookies.util.ts
import { Response } from 'express';
import { CookieOptions } from '@szept/types';

export function setAuthCookies(
  res: Response,
  access: string,
  refresh?: string,
  opts?: CookieOptions,
) {
  if (!opts) throw new Error('Cookie options are required');
  if (opts.secure === undefined)
    throw new Error('Cookie option "secure" must be explicitly set');

  const base = {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: opts.secure,
    domain: opts.domain,
  };

  // access token
  res.cookie('access_token', access, {
    ...base,
    path: '/',
    maxAge: opts.accessTtlSec * 1000,
    expires: new Date(Date.now() + opts.accessTtlSec * 1000),
  });

  // refresh token
  if (refresh) {
    const ttl = opts.refreshTtlSec ?? opts.accessTtlSec;
    res.cookie('refresh_token', refresh, {
      ...base,
      path: '/',
      maxAge: ttl * 1000,
      expires: new Date(Date.now() + ttl * 1000),
    });
  }
}

export function clearAuthCookies(
  res: Response,
  opts: { secure: boolean; domain?: string },
) {
  const base = {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: opts.secure,
    domain: opts.domain,
  };

  res.clearCookie('access_token', { ...base, path: '/' });
  res.clearCookie('refresh_token', { ...base, path: '/' });
}
