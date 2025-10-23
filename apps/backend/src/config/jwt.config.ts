// src/config/jwt.config.ts
export const jwtConfig = () => ({
  ISSUER: process.env.JWT_ISSUER || 'chat-app',
  AUDIENCE: process.env.JWT_AUDIENCE || 'chat-web',
  ACCESS_TTL: Number(process.env.JWT_ACCESS_TTL) || 15 * 60, // sekundy
  REFRESH_TTL: Number(process.env.JWT_REFRESH_TTL) || 7 * 24 * 60 * 60,
});
