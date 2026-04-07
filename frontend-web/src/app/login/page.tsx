"use client";

import { ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import LoginForm from "@/components/forms/LoginForm";
import { useAuth } from "@/hooks/useAuth";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL;

if (!API_BASE_URL) {
  throw new Error("Missing NEXT_PUBLIC_API_BASE_URL environment variable");
}

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();

  async function handleLogin(username: string, password: string) {
    await login(username, password);
    router.push("/dashboard");
  }

  function handleKeycloakLogin() {
    window.location.href = `${API_BASE_URL}/auth/keycloak/login`;
  }

  return (
    <div className="auth-page">
      <div className="auth-card">
        <div className="auth-brand">
          <div className="brand-badge">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1>NorthStar Insurance</h1>
            <p>Secure digital insurance operations platform</p>
          </div>
        </div>

        <LoginForm onSubmit={handleLogin} />

        <div className="demo-box">
          <h3>Demo accounts</h3>
          <p>admin1 / Password123!</p>
          <p>customer1 / Password123!</p>
        </div>

        <div className="demo-box">
          <h3>Single Sign-On</h3>
          <button
            className="btn btn-secondary"
            type="button"
            onClick={handleKeycloakLogin}
            style={{ width: "100%" }}
          >
            Sign in with Keycloak
          </button>
        </div>
      </div>
    </div>
  );
}