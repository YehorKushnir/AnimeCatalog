import {Prop, Schema, SchemaFactory} from "@nestjs/mongoose";
import mongoose, {HydratedDocument} from "mongoose";

export type UserDocument = HydratedDocument<User>

@Schema()
export class User {
    @Prop({required: true})
    username: string

    @Prop({required: true})
    email: string

    @Prop({required: true})
    password: string

    @Prop({
        type: [
            {
                token: {type: mongoose.Schema.Types.ObjectId, ref: 'Token'},
                expiresAt: {
                    type: Date,
                    expires: '60s',
                },
            },
        ],
    })
    tokens: Array<{token: {type: mongoose.Schema.Types.ObjectId, ref: 'Token'}; expiresAt: Date }>
}

export const UserSchema = SchemaFactory.createForClass(User)