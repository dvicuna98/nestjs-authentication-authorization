import {Body, Controller, Delete, Get, Param, Patch, Post} from '@nestjs/common';
import {CoffeesService} from './coffees.service';
import {CreateCoffeeDto} from './dto/create-coffee.dto';
import {UpdateCoffeeDto} from './dto/update-coffee.dto';
import {ActiveUser} from '../iam/decorators/active-user.decorator';
import {ActiveUserData} from '../iam/interfaces/active-user-data.interface';
import {Roles} from "../iam/authorization/decorators/roles.decorator";
import {Role} from "../users/enums/role.enum";
import {FrameworkContributorPolicy} from "../iam/authorization/policies/framework-contributor.policy";
import {Policies} from "../iam/authorization/decorators/policies.decorator";
import {Auth} from "../iam/authentication/decorators/auth.decorator";
import {AuthType} from "../iam/authentication/enums/auth-type.enum";

@Auth(AuthType.ApiKey, AuthType.Bearer)
@Controller('coffees')
export class CoffeesController {
  constructor(private readonly coffeesService: CoffeesService) {}

  // @Roles(Role.Admin)
  // @Permissions(Permission.CreateCoffee) // 👈
  @Policies(new FrameworkContributorPolicy())
  @Post()
  create(@Body() createCoffeeDto: CreateCoffeeDto) {
    return this.coffeesService.create(createCoffeeDto);
  }

  @Get()
  findAll(@ActiveUser() user:ActiveUserData) {
    return this.coffeesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.coffeesService.findOne(+id);
  }

  @Roles(Role.Admin)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateCoffeeDto: UpdateCoffeeDto) {
    return this.coffeesService.update(+id, updateCoffeeDto);
  }

  @Roles(Role.Admin)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.coffeesService.remove(+id);
  }
}
