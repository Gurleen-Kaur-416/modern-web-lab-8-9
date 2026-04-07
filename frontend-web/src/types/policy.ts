export interface Policy {
  _id: string;
  policyNumber: string;
  insuranceType: "LIFE" | "CAR" | "HOME";
  customerId: string;
  customerDisplay?: string;
  coverageAmount: number;
  premiumAmount: number;
  currency?: string;
  effectiveDate: string;
  expiryDate: string;
  status: string;
  beneficiaryName?: string | null;
  vehicleMake?: string | null;
  vehicleModel?: string | null;
  propertyAddress?: string | null;
  createdById?: string;
  createdByDisplay?: string;
  createdBy?: string;
  createdAt?: string;
  updatedAt?: string;
}