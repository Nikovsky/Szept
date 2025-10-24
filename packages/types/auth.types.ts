// packages/types/auth.types.ts
import { Request } from "express";

export interface CookieOptions {
  secure: boolean;
  domain?: string;
  csrf?: string;
  accessTtlSec: number;
  refreshTtlSec?: number;
}

export interface AccessPayload {
  sub: string;
  sid: string;
  iat?: number;
  exp?: number;
}

export interface SecurityEvent {
  type: "LOGIN" | "LOGOUT" | "REFRESH" | "REVOKE" | "REPLAY_DETECTED";
  userId: string;
  ip?: string;
  ua?: string;
  CreatedAt?: Date;
  details?: Record<string, unknown>;
}

export interface TokenBundle {
  access: string;
  refresh: string;
  csrf: string;
  accessTtlSec: number;
  refreshTtlSec: number;
}

export interface AuthRequest extends Request {
  user: { userId: string; sessionId: string };
}
