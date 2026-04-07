import { AmendmentRequest } from "../models/AmendmentRequest.js";

const amendmentPopulate = [
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

export const amendmentRepository = {
  findAll() {
    return AmendmentRequest.find()
      .populate(amendmentPopulate)
      .sort({ createdAt: -1 });
  },

  findById(id) {
    return AmendmentRequest.findById(id).populate(amendmentPopulate);
  },

  findByPolicyId(policyId) {
    return AmendmentRequest.find({ policy: policyId })
      .populate(amendmentPopulate)
      .sort({ createdAt: -1 });
  },

  findForCustomer(customerId) {
    return AmendmentRequest.find({ requestedBy: customerId })
      .populate(amendmentPopulate)
      .sort({ createdAt: -1 });
  },

  create(payload) {
    return AmendmentRequest.create(payload).then((created) =>
      AmendmentRequest.findById(created._id).populate(amendmentPopulate)
    );
  },

  updateById(id, payload) {
    return AmendmentRequest.findByIdAndUpdate(id, payload, {
      new: true,
      runValidators: true
    }).populate(amendmentPopulate);
  },

  deleteById(id) {
    return AmendmentRequest.findByIdAndDelete(id);
  }
};