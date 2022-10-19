import { NestFactory } from "@nestjs/core";
import cookieParser from "cookie-parser";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ["log", "error"],
  });
  app.use(cookieParser());
  app.enableCors();
  await app.listen(3000);
}
bootstrap();
