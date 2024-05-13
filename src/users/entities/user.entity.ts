import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';
import {Role} from "../enums/role.enum";
import {Permission, PermissionType} from "../../iam/authorization/permission.type";
@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ unique: true })
    email: string;

    @Column()
    password: string;

    @Column({ enum: Role, default: Role.Regular })
    role: Role;

    // 📝 ADDITIONS - user.entity.ts - add permissions prop
    // NOTE: Having the "permissions" column in combination with the "role"
    // likely does not make sense. We use both in this course just to showcase
    // two different approaches to authorization.
    @Column({ enum: Permission, default: [], type: 'json' })
    permissions: PermissionType[];
}
