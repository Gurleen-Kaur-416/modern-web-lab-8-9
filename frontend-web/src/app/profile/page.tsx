"use client";

import { useEffect, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import { apiRequest } from "@/lib/api";
import type { User } from "@/types/user";

export default function ProfilePage() {
  const [profile, setProfile] = useState<User | null>(null);

  useEffect(() => {
    async function load() {
      const response = await apiRequest<User>("/profile/me");
      setProfile(response.data);
    }

    void load();
  }, []);

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title="Profile"
          subtitle="Comprehensive user identity and business profile data."
        />

        {profile ? (
          <div className="profile-grid">
            <div className="panel">
              <h3>Identity</h3>
              <p><strong>Username:</strong> {profile.username}</p>
              <p><strong>Status:</strong> {profile.accountStatus}</p>
              <p><strong>Roles:</strong> {profile.roles.join(", ")}</p>
            </div>

            <div className="panel">
              <h3>Profile Details</h3>
              <p><strong>Name:</strong> {profile.profile.firstName} {profile.profile.lastName}</p>
              <p><strong>Email:</strong> {profile.profile.email}</p>
              <p><strong>Phone:</strong> {profile.profile.phone || "-"}</p>
              <p><strong>City:</strong> {profile.profile.city || "-"}</p>
              <p><strong>Country:</strong> {profile.profile.country || "-"}</p>
              <p><strong>User Type:</strong> {profile.profile.userType}</p>
            </div>
          </div>
        ) : null}
      </PageShell>
    </ProtectedRoute>
  );
}