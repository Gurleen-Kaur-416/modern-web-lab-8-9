export interface Role {
  _id: string;
  name: string;
  permissions: string[];
  createdAt?: string;
  updatedAt?: string;
}