import {Module} from '@nestjs/common';
import {AuthService} from './auth.service';
import {AuthController} from './auth.controller';
import {UserModule} from "../user/user.module";
import {JwtModule} from "@nestjs/jwt";
import {MongooseModule} from "@nestjs/mongoose";
import {Token, TokenSchema} from "./schemas/token.schema";

@Module({
	imports: [
		UserModule,
		JwtModule,
		MongooseModule.forFeature([{name: Token.name, schema: TokenSchema}])
	],
	controllers: [AuthController],
	providers: [AuthService],
})
export class AuthModule {
}
