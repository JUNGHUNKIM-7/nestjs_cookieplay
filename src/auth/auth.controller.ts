import {
    Body,
    Controller,
    HttpCode,
    HttpStatus,
    Post,
    UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Auth, JwtPayload, Token } from './types';
import { Public } from './utils/decorators/public.decorator';
import { User } from './utils/decorators/user.decorator';
import { RtGuard } from './utils/guards';

@Controller('auth')
export class AuthController implements Auth {
    constructor(private readonly authService: AuthService) {}

    @Public()
    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    // @Redirect('/', 301) // it also applied GlobalGuard(AtGuard)
    async signUp(
        @Body() dto: CreateAuthDto,
    ): Promise<Token> {
        return this.authService.signUp(dto);
    }

    @Public()
    @Post('signin')
    // @Redirect('/', 301)
    async signIn(
        @Body() dto: CreateAuthDto,
    ): Promise<Token> {
        return this.authService.signIn(dto);
    }

    // reflector(SetMetaData) -> guard -> Strategy -> Custom Decorator than contains payload -> service
    // injecting atToken -> guard -> strategy -> req.user(payload) -> extractd email from param deco
    @Post('signout')
    @HttpCode(HttpStatus.OK)
    async signOut(@User() user: JwtPayload): Promise<void> {
        return this.authService.signOut(user);
    }

    @Post('account')
    @HttpCode(HttpStatus.OK)
    async changePwd(
        @User() user: JwtPayload,
        @Body() body: UpdateAuthDto,
    ): Promise<void> {
        return this.authService.changePwd(user, body);
    }

    // injecting rtToken -> guard -> strategy(req, payload) -> req.user(payload) -> extractd email from param deco
    @Public()
    @UseGuards(RtGuard)
    @HttpCode(HttpStatus.OK)
    @Post('refresh')
    async refresh(@User() user: JwtPayload): Promise<Token> {
        return this.authService.refresh(user);
    }

    @HttpCode(HttpStatus.OK)
    @Post('debug')
    async deleteAllForDebug(): Promise<void> {
        return this.authService.deleteAllForDebug();
    }
}
