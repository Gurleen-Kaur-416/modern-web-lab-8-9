import { ReductionRequest } from "../models/ReductionRequest.js";
import { Policy } from "../models/Policy.js";

const reductionPopulate = [
  {
    path: "policy",
    populate: [
      {
        path: "customer",
        select: "username email fullName profile.firstName profile.lastName profile.email"
      },
      {
        path: "createdBy",
        select: "username email fullName profile.firstName profile.lastName profile.email"
      }
    ]
  },
  {
    path: "requestedBy",
    select: "username email fullName profile.firstName profile.lastName profile.email"
  },
  {
    path: "reviewedBy",
    select: "username email fullName profile.firstName profile.lastName profile.email"
  }
];

export const reductionRepository = {
  findAll() {
    return ReductionRequest.find()
      .populate(reductionPopulate)
      .sort({ createdAt: -1 });
  },

  findById(id) {
    return ReductionRequest.findById(id).populate(reductionPopulate);
  },

  findByPolicyId(policyId) {
    return ReductionRequest.find({ policy: policyId })
      .populate(reductionPopulate)
      .sort({ createdAt: -1 });
  },

  async findForCustomer(customerId) {
    const customerPolicies = await Policy.find({
      $or: [{ customer: customerId }, { customerId: customerId }]
    }).select("_id");

    const policyIds = customerPolicies.map((policy) => policy._id);

    return ReductionRequest.find({
      policy: { $in: policyIds }
    })
      .populate(reductionPopulate)
      .sort({ createdAt: -1 });
  },

  create(payload) {
    return ReductionRequest.create(payload).then((created) =>
      ReductionRequest.findById(created._id).populate(reductionPopulate)
    );
  },

  updateById(id, payload) {
    return ReductionRequest.findByIdAndUpdate(id, payload, {
      new: true,
      runValidators: true
    }).populate(reductionPopulate);
  },

  deleteById(id) {
    return ReductionRequest.findByIdAndDelete(id);
  }
};