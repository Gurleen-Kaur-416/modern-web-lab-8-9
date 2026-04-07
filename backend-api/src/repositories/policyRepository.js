import { Policy } from "../models/Policy.js";

const policyPopulate = [
  {
    path: "customer",
    select: "username email fullName profile.firstName profile.lastName profile.email"
  },
  {
    path: "createdBy",
    select: "username email fullName profile.firstName profile.lastName profile.email"
  }
];

export const policyRepository = {
  findAll() {
    return Policy.find()
      .populate(policyPopulate)
      .sort({ createdAt: -1 });
  },

  findById(id) {
    return Policy.findById(id).populate(policyPopulate);
  },

  findByCustomerId(customerId) {
    return Policy.find({ customer: customerId })
      .populate(policyPopulate)
      .sort({ createdAt: -1 });
  },

  create(payload) {
    return Policy.create(payload).then((created) =>
      Policy.findById(created._id).populate(policyPopulate)
    );
  },

  updateById(id, payload) {
    return Policy.findByIdAndUpdate(id, payload, {
      new: true,
      runValidators: true
    }).populate(policyPopulate);
  }
};