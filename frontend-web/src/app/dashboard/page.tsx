"use client";

import { useEffect, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import DashboardGrid from "@/components/dashboard/DashboardGrid";
import StatCard from "@/components/dashboard/StatCard";
import { apiRequest } from "@/lib/api";
import type { DashboardSummary } from "@/types/dashboard";

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);

  useEffect(() => {
    async function load() {
      const response = await apiRequest<DashboardSummary>("/dashboard/summary");
      setSummary(response.data);
    }

    void load();
  }, []);

  return (
    <ProtectedRoute>
      <PageShell>
        <SectionHeader
          title="Dashboard"
          subtitle="Unified secure workspace for customers, internal staff, and administrators."
        />

        <DashboardGrid>
          <StatCard title="Policies" value={summary?.policies ?? 0} subtitle="Protected insurance records" />
          <StatCard title="Claims" value={summary?.claims ?? 0} subtitle="Claims lifecycle" />
          <StatCard title="Amendments" value={summary?.amendments ?? 0} subtitle="Change requests" />
          <StatCard title="Reductions" value={summary?.reductions ?? 0} subtitle="Coverage adjustment requests" />
        </DashboardGrid>
      </PageShell>
    </ProtectedRoute>
  );
}