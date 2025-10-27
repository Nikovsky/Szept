export const fromB64u = (s: string) => Buffer.from(s, 'base64url');
export const toB64u = (b: Buffer) =>
  b
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
