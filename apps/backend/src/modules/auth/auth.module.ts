// apps/backend/src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaModule } from '@/prisma/prisma.module';
import { CleanupJob } from './jobs/cleanup.job';
import { JwtStrategy } from './jwt/jwt.strategy';
import { AuthConfigService } from '@/config/auth.config';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppConfigModule } from '@/config/config.module';

@Module({
  imports: [
    PrismaModule,
    AppConfigModule,
    JwtModule.registerAsync({
      imports: [AppConfigModule],
      inject: [AuthConfigService],
      useFactory: (authCfg: AuthConfigService) => ({
        secret: authCfg.accessSecret,
        signOptions: {
          expiresIn: authCfg.accessTtl, // liczba sekund → poprawny typ
          issuer: authCfg.issuer,
          audience: authCfg.audience,
        },
      }),
    }),
    ThrottlerModule.forRoot([{ ttl: 60, limit: 5 }]),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, CleanupJob, AuthConfigService],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
