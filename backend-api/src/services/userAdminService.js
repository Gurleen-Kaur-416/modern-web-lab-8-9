import { userRepository } from "../repositories/userRepository.js";
import { AppError } from "../utils/appError.js";
import { stripSensitiveUserFields } from "../utils/safeObject.js";

export const userAdminService = {
  async listUsers() {
    const users = await userRepository.findAll();
    return users.map(stripSensitiveUserFields);
  },

  async listCustomers() {
     const users = await userRepository.findCustomers();
    return users.map(stripSensitiveUserFields);
  },

  async updateUserStatus(userId, accountStatus) {
    const user = await userRepository.updateById(userId, { accountStatus });
    if (!user) {
      throw new AppError("User not found", 404);
    }
    return stripSensitiveUserFields(user);
  }
};