import {Injectable} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import {InjectModel} from "@nestjs/mongoose";
import {User, UserDocument} from "./schemas/user.schema";
import {Model} from "mongoose";

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {
  }

  async create(dto: CreateUserDto) {
    return this.userModel.create(dto)
  }

  async findAll() {
    return this.userModel.find()
  }

  async findOne(id: string) {
    return this.userModel.findById(id)
  }

  async findByEmail(email: string) {
    return this.userModel.findOne({email})
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  async remove(id: string) {
    return this.userModel.findByIdAndDelete(id)
  }
}
