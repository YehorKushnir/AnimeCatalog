import {Prop, Schema, SchemaFactory} from "@nestjs/mongoose";
import {HydratedDocument} from "mongoose";

export type TokenDocument = HydratedDocument<Token>

@Schema({
	timestamps: true
})
export class Token {
	@Prop()
	refreshToken: string

	@Prop({
		expires: 0
	})
	expiresAt: Date
}

export const TokenSchema = SchemaFactory.createForClass(Token)