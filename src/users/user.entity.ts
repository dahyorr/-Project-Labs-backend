import { Exclude } from 'class-transformer';
import { UserRole } from 'src/typings';
// import { RefreshToken } from 'src/entities/refresh-token.entity';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User{  
  @PrimaryGeneratedColumn()
  public id: number;

  @Column({
    default: UserRole.USER,
    type: 'enum',
    enum: UserRole,
  })
  public role: UserRole;

  @Column({
    unique: true
  })
  public email: string;

  @Column()
  public name: string;
  
  @Column()
  @Exclude()
  public password: string;
}