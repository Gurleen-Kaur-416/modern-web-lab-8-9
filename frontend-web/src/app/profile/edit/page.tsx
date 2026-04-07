"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import ProfileForm from "@/components/forms/ProfileForm";
import { apiRequest } from "@/lib/api";
import type { User, UserProfile } from "@/types/user";

export default function EditProfilePage() {
  const [profile, setProfile] = useState<User | null>(null);
  const router = useRouter();

  useEffect(() => {
    async function load() {
      const response = await apiRequest<User>("/profile/me");
      setProfile(response.data);
    }

    void load();
  }, []);

  async function handleSubmit(payload: Partial<UserProfile>) {
    await apiRequest<User>("/profile/me", {
      method: "PUT",
      body: payload
    });
    router.push("/profile");
  }

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title="Edit Profile"
          subtitle="Maintain your profile details securely."
        />

        {profile ? <ProfileForm initialValue={profile.profile} onSubmit={handleSubmit} /> : null}
      </PageShell>
    </ProtectedRoute>
  );
}