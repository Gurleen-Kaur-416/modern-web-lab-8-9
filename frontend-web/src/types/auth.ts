import type { User } from "./user";

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponseData {
  token: string;
  user: User;
}