// packages/types/auth.types.ts
import { Request } from "express";

export enum UserStatus {
  ONLINE,
  BUSY,
  OFFLINE,
}

export enum SecurityEventType {
  LOGIN,
  REFRESH,
  LOGOUT,
  REVOKE,
  REPLAY_DETECTED,
  SOCKET_CONNECT,
  SOCKET_DISCONNECT,
  MESSAGE_SEND,
}

export interface CookieOptions {
  secure: boolean;
  domain?: string;
  accessTtlSec: number;
  refreshTtlSec?: number;
}

export interface AuthPayload {
  sub: string;
  sessionId: string;
  familyId: string;
  role?: string[];
  iat?: number;
  exp?: number;
}

export interface SecurityEvent {
  type: SecurityEventType;
  userId: string;
  ip?: string;
  ua?: string;
  CreatedAt?: Date;
  details?: Record<string, unknown>;
}

export interface TokenBundle {
  access: string;
  refresh: string;
  accessTtlSec: number;
  refreshTtlSec: number;
}

export interface AuthRequest extends Request {
  user: { userId: string; sessionId: string; roles?: string[] };
}
