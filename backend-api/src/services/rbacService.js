import { roleRepository } from "../repositories/roleRepository.js";
import { userRepository } from "../repositories/userRepository.js";
import { AppError } from "../utils/appError.js";
import { stripSensitiveUserFields } from "../utils/safeObject.js";

export const rbacService = {
  async listRoles() {
    return roleRepository.findAll();
  },

  async assignRoles(userId, roles) {
    const validRoles = await roleRepository.findByNames(roles);

    if (validRoles.length !== roles.length) {
      throw new AppError("One or more roles are invalid", 400);
    }

    const user = await userRepository.updateById(userId, { roles });
    if (!user) {
      throw new AppError("User not found", 404);
    }

    return stripSensitiveUserFields(user);
  }
};