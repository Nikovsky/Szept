// packages/types/auth.types.ts
export interface CookieOptions {
  secure: boolean;
  domain?: string;
  csrf?: string;
  accessTtlSec: number;
  refreshTtlSec?: number;
}
