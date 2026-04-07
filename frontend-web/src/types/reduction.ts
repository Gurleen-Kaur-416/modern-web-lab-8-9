export interface ReductionRequest {
  _id: string;
  policyId: string;
  policyNumber?: string;
  customerDisplay?: string;
  requestedBy: string;
  requestedByDisplay?: string;
  currentCoverage: number;
  requestedCoverage: number;
  reason: string;
  status: string;
  reviewedBy?: string;
  reviewedByDisplay?: string;
  reviewComment?: string;
  createdAt?: string;
  updatedAt?: string;
}