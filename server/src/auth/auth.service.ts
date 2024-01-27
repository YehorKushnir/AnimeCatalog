import {HttpException, HttpStatus, Injectable} from '@nestjs/common';
import {LoginAuthDto} from "./dto/login-auth.dto";
import * as bcrypt from "bcrypt";
import {UserService} from "../user/user.service";
import {JwtService} from "@nestjs/jwt";
import {CreateUserDto} from "../user/dto/create-user.dto";
import {User} from "../user/schemas/user.schema";
import {InjectModel} from "@nestjs/mongoose";
import {Model} from "mongoose";
import {Token, TokenDocument} from "./schemas/token.schema";
import * as process from 'process';

@Injectable()
export class AuthService {
    constructor(
        private userService: UserService,
        private jwtService: JwtService,
		@InjectModel(Token.name) private tokenModel: Model<TokenDocument>
    ) {}

    async register({username, email, password}: CreateUserDto) {
        const candidate = await this.userService.findByEmail(email)
        if (candidate) {
            throw new HttpException('User already exist', HttpStatus.BAD_REQUEST)
        }

        const hash = await bcrypt.hash(password, 3)
        const user = await this.userService.create({username, email, password: hash})
        const tokens = await this.generateTokens(user)
		await this.saveToken(tokens.refreshToken)

        return tokens
    }

    async login({email, password}: LoginAuthDto) {
		const user = await this.userService.findByEmail(email)
		if (!user) {
			throw new HttpException("User does not exist", HttpStatus.BAD_REQUEST)
		}
		if (!await bcrypt.compare(password, user.password)) {
			throw new HttpException("Wrong password", HttpStatus.BAD_REQUEST)
		}

		const tokens = await this.generateTokens(user)
		await this.saveToken(tokens.refreshToken)

		return tokens
    }

    async refresh(refreshToken: string) {
		if (!refreshToken) {
			throw new HttpException("Token does not exist", HttpStatus.UNAUTHORIZED)
		}

		const user = await this.validateRefreshToken(refreshToken)
		const tokens = await this.generateTokens(user)
		const token = await this.findToken(refreshToken)
		token.refreshToken = tokens.refreshToken;
		token.expiresAt = new Date(Date.now() + (60000 * +process.env.JWT_REFRESH_TTL));
		await token.save();

		return tokens
    }

    async logout(refreshToken: string) {
		return this.tokenModel.findOneAndDelete({refreshToken});
    }

	private async findToken(refreshToken: string) {
		return this.tokenModel.findOne({refreshToken})
	}

    private async generateTokens(user: User) {
		const payload = {username: user.username, email: user.email}
		return {
			refreshToken: this.jwtService.sign(payload, {
				secret: process.env.JWT_REFRESH_SECRET,
				expiresIn: `${process.env.JWT_REFRESH_TTL}m`
			}),
			accessToken: this.jwtService.sign(payload, {
				secret: process.env.JWT_ACCESS_SECRET,
				expiresIn: `${process.env.JWT_ACCESS_TTL}m`,
			}),
		}
    }

	private async saveToken(refreshToken: string) {
		const expiresAt = new Date(Date.now() + (60000 * +process.env.JWT_REFRESH_TTL))
		return this.tokenModel.create({refreshToken, expiresAt})
	}

	private async validateRefreshToken(refreshToken: string) {
		try {
			return this.jwtService.verify(refreshToken, {secret: process.env.JWT_REFRESH_SECRET})
		} catch {
			throw new HttpException("Token has expired", HttpStatus.UNAUTHORIZED)
		}
	}
}
