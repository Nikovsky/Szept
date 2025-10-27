import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '@/prisma/prisma.service';

@Injectable()
export class CleanupJob {
  private readonly log = new Logger(CleanupJob.name);

  constructor(private readonly prisma: PrismaService) {}

  @Cron('0 * * * *') // co godzinę
  async removeExpiredSessions() {
    const deleted = await this.prisma.refreshSession.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
    if (deleted.count > 0)
      this.log.log(`🧹 Deleted ${deleted.count} expired sessions`);
  }
}
