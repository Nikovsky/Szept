import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthConfigService } from './auth.config';

@Module({
  imports: [ConfigModule.forRoot({ isGlobal: true })],
  providers: [AuthConfigService],
  exports: [AuthConfigService],
})
export class AppConfigModule {}
