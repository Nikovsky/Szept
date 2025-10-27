import { UAParser } from 'ua-parser-js';
import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import { DeviceInfo } from '@szept/types';

dayjs.extend(relativeTime);

export function parseUserAgent(ua?: string | null): DeviceInfo {
  if (!ua) return { os: 'Unknow OS', browser: 'Unknown', device: 'Unknown' };

  const parser = new UAParser(ua);

  const os = parser.getOS()?.name || 'Unknow OS';
  const browser = parser.getBrowser()?.name || 'Unknow Browser';
  const device = parser.getDevice()?.model || 'Desktop';
  return { os, browser, device };
}

export function humanTime(date: Date | null): string {
  if (!date) return 'n/a';
  return dayjs(date).fromNow();
}
