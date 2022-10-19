import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { ForbiddenException, Injectable } from "@nestjs/common";
import { JwtPayload } from "../types";
import { PrismaService } from "src/prisma/prisma.service";
import * as argon from "argon2";
import { Request } from "express";

@Injectable()
export class RtStrategy extends PassportStrategy(Strategy, "rt-jwt") {
  constructor(private readonly p: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: "rt-secret",
      passReqToCallback: true,
    });
  }

  async validate(
    req: Request,
    payload: JwtPayload,
  ): Promise<JwtPayload> {
    const { rToken } = await this.p.user.findUnique({
      where: { email: payload.email },
    });
    const rt = req.header("authorization").split(" ").at(-1).trim();
    const rtMatches = await argon.verify(
      rToken,
      rt,
    );

    if (!rtMatches) {
      throw new ForbiddenException("rt not matches");
    } else {
      return {
        ...payload,
        rt,
      };
    }
  }
}
