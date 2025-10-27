// apps/backend/src/config/auth/config.ts
import { z } from 'zod';
import { Injectable } from '@nestjs/common';

const authSchema = z.object({
  JWT_ACCESS_SECRET: z
    .string()
    .min(32, 'JWT_ACCESS_SECRET must be at least 32 chars'),
  JWT_ISSUER: z.string().min(1),
  JWT_AUDIENCE: z.string().min(1),
  JWT_ACCESS_TTL: z.coerce.number().default(15 * 60), // 15 min
  JWT_REFRESH_TTL: z.coerce.number().default(7 * 24 * 60 * 60), // 7 dni
  IP_HASH_SALT: z.string().min(16),
  UA_HASH_SALT: z.string().min(16),
  MAX_SESSIONS: z.coerce.number().default(5),
  ENABLE_SESSION_REUSE: z
    .string()
    .transform((v) => v === 'true')
    .default(false),

  ARGON_MEMORY: z.coerce.number().default(19456),
  ARGON_TIME: z.coerce.number().default(2),
  ARGON_PARALLELISM: z.coerce.number().default(1),
});

export type AuthConfig = z.infer<typeof authSchema>;

@Injectable()
export class AuthConfigService {
  private readonly cfg: AuthConfig;

  constructor() {
    const parsed = authSchema.safeParse(process.env);
    if (!parsed.success) {
      console.error(
        '❌ Invalid auth configuration:',
        parsed.error.flatten().fieldErrors,
      );
      throw new Error('Invalid Auth configuration (.env)');
    }
    this.cfg = parsed.data;
  }

  get issuer() {
    return this.cfg.JWT_ISSUER;
  }
  get audience() {
    return this.cfg.JWT_AUDIENCE;
  }
  get accessSecret() {
    return this.cfg.JWT_ACCESS_SECRET;
  }
  get accessTtl() {
    return this.cfg.JWT_ACCESS_TTL;
  }
  get refreshTtl() {
    return this.cfg.JWT_REFRESH_TTL;
  }
  get ipSalt() {
    return this.cfg.IP_HASH_SALT;
  }
  get uaSalt() {
    return this.cfg.UA_HASH_SALT;
  }
  get maxSessions() {
    return this.cfg.MAX_SESSIONS;
  }
  get reuse() {
    return this.cfg.ENABLE_SESSION_REUSE;
  }
  get argonMemory() {
    return this.cfg.ARGON_MEMORY;
  }
  get argonTime() {
    return this.cfg.ARGON_TIME;
  }
  get argonParallelism() {
    return this.cfg.ARGON_PARALLELISM;
  }
}
