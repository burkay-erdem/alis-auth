import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth.service';

@Injectable()
export class IpCheckMiddleware implements NestMiddleware {
    constructor(private readonly jwtService: JwtService) { }

    use(req: Request, res: Response, next: NextFunction) {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) {
            throw new UnauthorizedException('Access Token missing');
        }

        try {
            const payload = this.jwtService.verify(token);
            const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;

            const clientIp = ip == '::1' ? '127.0.0.1' : ip

            if (payload.ip !== clientIp) {
                throw new UnauthorizedException('IP address mismatch');
            }

            next();
        } catch (error) {
            throw new UnauthorizedException('Invalid token');
        }
    }
}
