import { Test, TestingModule } from '@nestjs/testing';
import { E2eeService } from './e2ee.service';

describe('E2eeService', () => {
  let service: E2eeService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [E2eeService],
    }).compile();

    service = module.get<E2eeService>(E2eeService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
