import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtPayload } from './auth/types';
import { User } from './auth/utils/decorators/user.decorator';

@Controller()
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get()
    async getHello(@User() user: JwtPayload): Promise<string> {
        return this.appService.getHello(user);
    }
}
