export interface Claim {
  _id: string;
  policyId: string;
  policyNumber?: string;
  customerDisplay?: string;
  claimedBy: string;
  claimedByDisplay?: string;
  claimType: string;
  incidentDate: string;
  amount: number;
  description: string;
  status: string;
  reviewedBy?: string;
  reviewedByDisplay?: string;
  reviewComment?: string;
  createdAt?: string;
  updatedAt?: string;
}