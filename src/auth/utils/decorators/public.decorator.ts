import { SetMetadata } from "@nestjs/common";

export const Public = (vals: any[] = [true]) => SetMetadata("isPublic", vals);
