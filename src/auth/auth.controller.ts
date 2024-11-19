
import {
    Body,
    Controller,
    Get,
    HttpCode,
    HttpStatus,
    Ip,
    Post,
    Req,
    Request,
    UnauthorizedException,
    UseGuards
} from '@nestjs/common';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @HttpCode(HttpStatus.OK)
    @Post('login')
    async signIn(@Body() signInDto: { username: string, password: string }, @Ip() ip) {

        const clientIp = this.authService.getIpAddress(ip)

        const user = await this.authService.validateUser(signInDto.username, signInDto.password);
        if (!user) {
            throw new UnauthorizedException();
        }
      

        const accessToken = await this.authService.generateAccessToken({ username: signInDto.username, password: signInDto.password, ip: clientIp });
        const refreshToken = await this.authService.generateRefreshToken({ ip: clientIp });

        return {
            accessToken,
            refreshToken
        }
    }

    @Post('refresh-token')
    async refreshToken(@Body('refreshToken') refreshToken: string, @Ip() ip) {
         
        try {
            const payload = await this.authService.verifyToken(refreshToken);
            const clientIp = this.authService.getIpAddress(ip)
   
            if (payload.ip !== clientIp) {
                throw new UnauthorizedException('IP address mismatch');
            }

            const newAccessToken = await this.authService.generateAccessToken({ username: payload.username, password: payload.password, ip: clientIp });
            const newRefreshToken = await this.authService.generateRefreshToken({ ip: clientIp });

            return { accessToken: newAccessToken, refreshToken: newRefreshToken };
        } catch (error) {
            throw new UnauthorizedException('Invalid Refresh Token');
        }
    }


   
}
