"use client";

import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/useAuth";

export default function Topbar() {
  const { user, logout } = useAuth();
  const router = useRouter();

  return (
    <header className="topbar">
      <div>
        <h2>Secure Operations Workspace</h2>
        <p>
          {user?.profile.firstName} {user?.profile.lastName}
        </p>
      </div>
      <button
        className="btn btn-secondary"
        onClick={() => {
          logout();
          router.push("/login");
        }}
      >
        Logout
      </button>
    </header>
  );
}