import { Controller, Get } from '@nestjs/common';
import { HealthService } from './health.service';
import { timestamp } from 'rxjs';

@Controller('health')
export class HealthController {
  constructor(private healthService: HealthService) {}

  @Get('db')
  async checkDatabase() {
    const isConnected = await this.healthService.checkDatabase();
    return {
      status: isConnected ? 'ok' : 'error',
      database: isConnected ? 'connected' : 'disconnected',
      timestamp: new Date().toISOString(),
    };
  }
}
