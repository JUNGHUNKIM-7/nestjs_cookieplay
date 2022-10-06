import { createParamDecorator, ExecutionContext } from '@nestjs/common';

//JWTSTRATEGY returns Object(payload) then set to REQ.USER automatically
export const User = createParamDecorator(
    (data: unknown, ctx: ExecutionContext) => {
        const request = ctx.switchToHttp().getRequest();
        if (!data) {
            return request.user;
        } else {
            return request.user[String(data) as string];
        }
    },
);
