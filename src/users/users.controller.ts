import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/currentUser.decorator';
import { User } from './user.entity';
import { UsersService } from './users.service';

@UseGuards(JwtAuthGuard)
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService){}

  @Get('details')
  getProfile(@CurrentUser() user: Partial<User>) {
    return user;
  }
}
