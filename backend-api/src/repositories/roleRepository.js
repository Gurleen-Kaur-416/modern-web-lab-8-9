import { Role } from "../models/Role.js";

export const roleRepository = {
  findAll() {
    return Role.find().sort({ name: 1 });
  },
  findByNames(names) {
    return Role.find({ name: { $in: names } });
  },
  create(payload) {
    return Role.create(payload);
  }
};