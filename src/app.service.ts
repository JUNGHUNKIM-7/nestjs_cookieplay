import { Injectable } from '@nestjs/common';
import { JwtPayload } from './auth/types';
import { User } from './auth/utils/decorators/user.decorator';

@Injectable()
export class AppService {
    async getHello(@User() user: JwtPayload): Promise<string> {
        return user.email;
    }
}
