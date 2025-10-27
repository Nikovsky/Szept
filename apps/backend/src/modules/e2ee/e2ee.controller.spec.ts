import { Test, TestingModule } from '@nestjs/testing';
import { E2eeController } from './e2ee.controller';

describe('E2eeController', () => {
  let controller: E2eeController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [E2eeController],
    }).compile();

    controller = module.get<E2eeController>(E2eeController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
