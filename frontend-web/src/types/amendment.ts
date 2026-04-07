export interface AmendmentChange {
  field: string;
  currentValue: string;
  requestedValue: string;
}

export interface AmendmentRequest {
  _id: string;
  policyId: string;
  policyNumber?: string;
  customerDisplay?: string;
  requestedBy: string;
  requestedByDisplay?: string;
  changes: AmendmentChange[];
  reason: string;
  status: string;
  reviewedBy?: string;
  reviewedByDisplay?: string;
  reviewComment?: string;
  createdAt?: string;
  updatedAt?: string;
}