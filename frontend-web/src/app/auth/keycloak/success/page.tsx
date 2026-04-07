"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { saveKeycloakSession } from "@/lib/auth";
import type { User } from "@/types/user";

export default function KeycloakSuccessPage() {
  const router = useRouter();
  const [error, setError] = useState("");

  useEffect(() => {
    async function finalizeKeycloakSession() {
      try {
        const response = await api.get<User>("/profile/me");
        saveKeycloakSession(response.data);
        router.replace("/dashboard");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to complete Keycloak sign-in.");
      }
    }

    void finalizeKeycloakSession();
  }, [router]);

  return (
    <div className="center-screen">
      <div className="panel small-panel">
        {error ? (
          <>
            <h2>Keycloak sign-in failed</h2>
            <p>{error}</p>
          </>
        ) : (
          <>
            <div className="loader-spinner" />
            <h2>Completing sign-in</h2>
            <p>Please wait while we load your profile.</p>
          </>
        )}
      </div>
    </div>
  );
}