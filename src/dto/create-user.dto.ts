import {IsEmail, IsNotEmpty, IsString, Length} from 'class-validator'

export class CreateUserDto{
    @IsEmail()
    public email: string;

    @IsString()
    @Length(4)
    public password: string;

    @IsString()
    @IsNotEmpty()
    public name: string;
}