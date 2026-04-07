import { Policy } from "../models/Policy.js";
import { Claim } from "../models/Claim.js";
import { AmendmentRequest } from "../models/AmendmentRequest.js";
import { ReductionRequest } from "../models/ReductionRequest.js";

export const dashboardService = {
  async getSummary() {
    const [policies, claims, amendments, reductions] = await Promise.all([
      Policy.countDocuments(),
      Claim.countDocuments(),
      AmendmentRequest.countDocuments(),
      ReductionRequest.countDocuments()
    ]);

    return {
      policies,
      claims,
      amendments,
      reductions
    };
  }
};