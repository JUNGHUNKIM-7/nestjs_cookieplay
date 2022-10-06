import {
    Body,
    Controller,
    HttpCode,
    HttpStatus,
    Post,
    Redirect,
    Req,
    Res,
    UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { Auth, JwtPayload } from './types';
import { Public } from './utils/decorators/public.decorator';
import { User } from './utils/decorators/user.decorator';
import { RtGuard } from './utils/guards';

@Controller('auth')
export class AuthController implements Auth {
    constructor(private readonly authService: AuthService) {}

    @Public()
    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    @Redirect('/', 301) // it also applied GlobalGuard(AtGuard)
    async signUp(
        @Body() dto: CreateAuthDto,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ): Promise<void> {
        return this.authService.signUp(dto, req, res);
    }

    @Public()
    @Post('signin')
    @HttpCode(HttpStatus.OK)
    @Redirect('/', 301)
    async signIn(
        @Body() dto: CreateAuthDto,
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ): Promise<void> {
        return this.authService.signIn(dto, req, res);
    }

    // reflector(SetMetaData) -> guard -> Strategy -> Custom Decorator than contains payload -> service
    //injecting at token -> guard -> strategy -> req.user(payload) -> extractd email from param deco
    @Post('signout')
    @HttpCode(HttpStatus.OK)
    async signOut(@User() user: JwtPayload): Promise<void> {
        return this.authService.signOut(user);
    }

    async chagnePassword(payload: JwtPayload): Promise<void> {
        throw new Error('Method not implemented.');
    }

    //injecting rt token + payload -> guard -> strategy(req, payload) -> req.user(payload) -> extractd email from param deco
    @Public()
    @UseGuards(RtGuard)
    @HttpCode(HttpStatus.OK)
    @Post('refresh')
    async refresh(@User() user: JwtPayload): Promise<void> {
        return this.authService.refresh(user);
    }
}
