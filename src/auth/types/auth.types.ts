import { Request, Response } from 'express';
import { CreateAuthDto } from '../dto/create-auth.dto';
import { UpdateAuthDto } from '../dto/update-auth.dto';

export interface Token {
    at: string;
    rt: string;
}

export interface Auth {
    signUp(dto: CreateAuthDto, req: Request, res: Response): Promise<void>;
    signIn(dto: CreateAuthDto, req: Request, res: Response): Promise<void>;
    signOut(payload: JwtPayload): Promise<void>;
    changePwd(payload: JwtPayload, body: UpdateAuthDto): Promise<void>;
    refresh(payload: JwtPayload): Promise<void>;
}

export interface JwtPayload {
    sub: string;
    email: string;
    rt?: string;
}
