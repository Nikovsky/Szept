import { Module } from '@nestjs/common';
import { E2eeService } from './e2ee.service';
import { E2eeController } from './e2ee.controller';
import { PrismaService } from '@/prisma/prisma.service';

@Module({
  controllers: [E2eeController],
  providers: [E2eeService, PrismaService],
})
export class E2eeModule {}
