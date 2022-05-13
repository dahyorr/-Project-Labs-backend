import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { CreateUserDto } from '../dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private usersRepository: Repository<User>){}

  async create(userDto: CreateUserDto) {
    const user = this.usersRepository.create(userDto);
    return await this.usersRepository.save(user)
  }

  async findOneByEmail(email: string) {
    const user = this.usersRepository.findOneBy({ email });
    return user;
  }
}
