export interface UserProfile {
  firstName: string;
  lastName: string;
  dateOfBirth?: string;
  email: string;
  phone?: string;
  addressLine1?: string;
  addressLine2?: string;
  city?: string;
  province?: string;
  postalCode?: string;
  country?: string;
  customerNumber?: string;
  employeeNumber?: string;
  userType: string;
  preferredContactMethod?: string;
  emergencyContactName?: string;
  emergencyContactPhone?: string;
  department?: string;
  jobTitle?: string;
  supervisorName?: string;
  internalAccessStatus?: string;
}

export interface User {
  _id: string;
  username: string;
  roles: string[];
  accountStatus: string;
  profile: UserProfile;
  createdAt?: string;
  updatedAt?: string;
}