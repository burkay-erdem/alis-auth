
import { Injectable, Ip, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from './constants';

interface IUserTokenPayload {
    username: string,
    password: string,
    ip: string
}

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService
    ) { }

    async validateUser(username: string, pass: string): Promise<any> {
        const user = await this.usersService.findOne(username);
        if (user && user.password === pass) {
            const { password, ...result } = user;
            return result;
        }
        return null;
    }

    async generateAccessToken(payload: IUserTokenPayload): Promise<string> {
        return this.jwtService.signAsync(payload, { expiresIn: '15m' });
    }

    async generateRefreshToken(payload: Pick<IUserTokenPayload, "ip">): Promise<string> {
        return this.jwtService.signAsync(payload, { expiresIn: '7d' });
    }

    async verifyToken(token: string) {
        try {
            return this.jwtService.verifyAsync(
                token,
                {
                    secret: jwtConstants.secret
                }
            );
        } catch (error) {
            throw new Error('Invalid Token');
        }
    }
    getIpAddress(@Ip() ip) {
        return ip == '::1' ? '127.0.0.1' : ip
    }
}
