// packages/types/session.type.ts
export interface SessionInfo {
  id: string;
  familyId: string;
  createdAt: string;
  lastUsedAt?: string | null;
  expiresAt: string;
  ipHash?: string | null;
  uaHash?: string | null;
  active: boolean;
}

export interface DeviceInfo {
  os: string;
  browser: string;
  device: string;
}
