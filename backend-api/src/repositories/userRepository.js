import { User } from "../models/User.js";

export const userRepository = {
  findByUsername(username) {
    return User.findOne({ username }).populate("roles");
  },

  findByEmail(email) {
    return User.findOne({
      "profile.email": String(email).toLowerCase().trim()
    }).populate("roles");
  },

  findById(id) {
    return User.findById(id).populate("roles");
  },

  findByNames(names) {
    return Role.find({ name: { $in: names } });
  },

  findAll() {
    return User.find().populate("roles");
  },

  create(data) {
    return User.create(data);
  },

  updateById(id, update) {
    return User.findByIdAndUpdate(id, update, { new: true }).populate("roles");
  },

  async findCustomers() {
  return User.find()
    .populate({
      path: "roles",
      match: { name: "CUSTOMER" }
    })
    .then(users => users.filter(user => user.roles.length > 0));
  } 
};