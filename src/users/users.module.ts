import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { IpCheckMiddleware } from 'src/auth/auth.middleware';

@Module({
  providers: [UsersService],
  exports: [UsersService],
  controllers: [UsersController],
})
export class UsersModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(IpCheckMiddleware)
      .forRoutes('users');
  }
}
