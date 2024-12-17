import { PrismaService } from '../prisma/prisma.service';
import { ForbiddenException, Injectable } from "@nestjs/common";
import { AuthDto } from './dto';
import * as argon from "argon2"
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt:JwtService) {}
    async signup(dto: AuthDto) {
       try {
        const hashPassword = await argon.hash(dto.password);

        const user = await this.prisma.user.create({
            data:{
                email: dto.email,
                password: hashPassword
            }
        })
        delete dto.password;
        return user;
       } catch (error) {
        if( error instanceof PrismaClientKnownRequestError){
            if(error.code === 'P2002'){
                throw new ForbiddenException('Credentials not available');
            }
        }else{
            throw error;
        }
       }
    }

    async signin(dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        });
        if(!user){
            throw new ForbiddenException('Credentials incorrect');
        };

        const pwMatches = await argon.verify(user.password, dto.password);

        if(!pwMatches){
            throw new ForbiddenException('Credentials incorrect');
        };
        return  this.signToken(user.id,user.email);
    }

    async signToken(userId: string, email:string): Promise<{access_token: string}>{
        const payload ={
            sub: userId,
            email
        }
        const token = await this.jwt.signAsync(payload, {
            expiresIn: '15m',
            secret: process.env.JWT_SECRET
        });
        return {
            access_token: token
        }
    }
}