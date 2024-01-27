import {Prop, Schema, SchemaFactory} from "@nestjs/mongoose";
import {HydratedDocument} from "mongoose";
import * as process from 'process';

export type TokenDocument = HydratedDocument<Token>

@Schema({
	timestamps: true,
})
export class Token {
	@Prop()
	refreshToken: string

	@Prop({
		expires: 60 * +process.env.JWT_REFRESH_TTL
	})
	expiresAt: Date
}

export const TokenSchema = SchemaFactory.createForClass(Token)