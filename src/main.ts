import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable session storage for PKCE code_verifier
  app.use(
    session({
      secret: 'your_secret_key',
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false }, // Set to true in production with HTTPS
    }),
  );
  app.enableCors();

  await app.listen(3001);
}
bootstrap();
