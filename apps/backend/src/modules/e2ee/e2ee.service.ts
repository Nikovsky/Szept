import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import {
  OneTimeBatchDto,
  RegisterDeviceDto,
  SignedPreKeyDto,
  VerifyDeviceDto,
} from './dto/e2ee.dto';
import { createHash } from 'crypto';
import { fromB64u, toB64u } from './util/b64';

@Injectable()
export class E2eeService {
  constructor(private readonly db: PrismaService) {}

  async registerDevice(userId: string, dto: RegisterDeviceDto) {
    // fingerprint = SHA-256(idKeyPub || signKeyPub)
    const fingerprint = this.fingerprint(dto.idKeyPubB64, dto.signKeyPubB64);

    // unikalność fingerprintu
    const exists = await this.db.device.findUnique({ where: { fingerprint } });
    if (exists)
      throw new ConflictException('device fingerprint already exists');

    const device = await this.db.$transaction(async (tx) => {
      const created = await tx.device.create({
        data: {
          userId,
          name: dto.name,
          platform: dto.platform,
          idKeyPub: fromB64u(dto.idKeyPubB64),
          signKeyPub: fromB64u(dto.signKeyPubB64),
          fingerprint,
          signedPreKeys: {
            create: {
              keyId: dto.signedPreKey.keyId,
              pub: fromB64u(dto.signedPreKey.pubB64),
              signature: fromB64u(dto.signedPreKey.signatureB64),
              isCurrent: true,
            },
          },
          oneTimePreKeys: {
            create: (dto.oneTime ?? []).map((k) => ({
              keyId: k.keyId,
              pub: fromB64u(k.pubB64),
            })),
          },
        },
        select: { id: true, fingerprint: true },
      });
      return created;
    });

    return device; // { id, fingerprint }
  }

  private fingerprint(idKeyB64: string, signKeyB64: string) {
    const buf = Buffer.concat([fromB64u(idKeyB64), fromB64u(signKeyB64)]);
    return createHash('sha256').update(buf).digest('base64url');
  }

  async issueBundle(deviceId: string) {
    const dev = await this.db.device.findUnique({
      where: { id: deviceId },
      include: {
        signedPreKeys: {
          where: { isCurrent: true },
          take: 1,
        },
        oneTimePreKeys: {
          where: { consumedAt: null },
          orderBy: { keyId: 'asc' },
          take: 1,
        },
      },
    });

    if (!dev) throw new NotFoundException('device not found');

    const signedPre = dev.signedPreKeys[0];
    const oneTime = dev.oneTimePreKeys[0];

    if (oneTime) {
      await this.db.oneTimePreKey.update({
        where: { id: oneTime.id },
        data: { consumedAt: new Date() },
      });
    }

    return {
      idKeyPubB64: toB64u(Buffer.from(dev.idKeyPub)),
      signKeyPubB64: toB64u(Buffer.from(dev.signKeyPub)),
      signedPreKey: signedPre
        ? {
            keyId: signedPre.keyId,
            pubB64: toB64u(Buffer.from(signedPre.pub)),
            signatureB64: toB64u(Buffer.from(signedPre.signature)),
          }
        : null,
      oneTimePreKey: oneTime
        ? {
            keyId: oneTime.keyId,
            pubB64: toB64u(Buffer.from(oneTime.pub)),
          }
        : null,
    };
  }

  async uploadOneTime(deviceId: string, dto: OneTimeBatchDto) {
    const device = await this.db.device.findUnique({ where: { id: deviceId } });
    if (!device) throw new NotFoundException('device not found');

    const created = await this.db.$transaction(
      dto.items.map((k) =>
        this.db.oneTimePreKey.create({
          data: {
            deviceId,
            keyId: k.keyId,
            pub: fromB64u(k.pubB64),
          },
        }),
      ),
    );

    return { stored: created.length };
  }

  async rotateSigned(deviceId: string, dto: SignedPreKeyDto) {
    const device = await this.db.device.findUnique({ where: { id: deviceId } });
    if (!device) throw new NotFoundException('device not found');

    await this.db.$transaction([
      this.db.signedPreKey.updateMany({
        where: { deviceId, isCurrent: true },
        data: { isCurrent: false },
      }),
      this.db.signedPreKey.create({
        data: {
          deviceId,
          keyId: dto.keyId,
          pub: fromB64u(dto.pubB64),
          signature: fromB64u(dto.signatureB64),
          isCurrent: true,
        },
      }),
    ]);

    return { ok: true };
  }

  async verifyDevice(deviceId: string, dto: VerifyDeviceDto) {
    const device = await this.db.device.findUnique({ where: { id: deviceId } });
    if (!device) throw new NotFoundException('device not found');

    if (device.fingerprint !== dto.fingerprint) {
      throw new ForbiddenException('fingerprint mismatch');
    }

    await this.db.device.update({
      where: { id: deviceId },
      data: { isVerified: true, lastSeenAt: new Date() },
    });

    return { verified: true, method: dto.method };
  }
}
