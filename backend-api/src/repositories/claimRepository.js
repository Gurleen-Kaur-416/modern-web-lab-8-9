import { Claim } from "../models/Claim.js";

const claimPopulate = [
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
    path: "claimedBy",
    select: "username email fullName profile.firstName profile.lastName profile.email"
  },
  {
    path: "reviewedBy",
    select: "username email fullName profile.firstName profile.lastName profile.email"
  }
];

export const claimRepository = {
  findAll() {
    return Claim.find()
      .populate(claimPopulate)
      .sort({ createdAt: -1 });
  },

  findById(id) {
    return Claim.findById(id).populate(claimPopulate);
  },

  findForCustomer(customerId) {
    return Claim.find({ claimedBy: customerId })
      .populate(claimPopulate)
      .sort({ createdAt: -1 });
  },

  findApprovedByPolicyId(policyId) {
    return Claim.find({
      policy: policyId,
      status: "APPROVED"
    }).populate(claimPopulate);
  },

  async sumApprovedAmountByPolicyId(policyId) {
    return Claim.aggregate([
      {
        $match: {
          policy: typeof policyId === "string" ? Claim.db.base.Types.ObjectId.createFromHexString(policyId) : policyId,
          status: "APPROVED"
        }
      },
      {
        $group: {
          _id: "$policy",
          total: { $sum: "$amount" }
        }
      }
    ]).then((rows) => (rows[0]?.total ?? 0));
  },

  async create(payload) {
    return Claim.create(payload).then((created) =>
      Claim.findById(created._id).populate(claimPopulate)
    );
  },

  updateById(id, payload) {
    return Claim.findByIdAndUpdate(id, payload, {
      new: true,
      runValidators: true
    }).populate(claimPopulate);
  },

  findByStatus(status) {
  return Claim.find({ status })
    .populate(claimPopulate)
    .sort({ createdAt: -1 });
  },

  deleteById(id) {
    return Claim.findByIdAndDelete(id);
  }
};