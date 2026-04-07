"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import PolicyForm, {
  type PolicyCustomerOption,
  type PolicyFormValues
} from "@/components/forms/PolicyForm";
import { api } from "@/lib/api";

export default function CreatePolicyPage() {
  const router = useRouter();
  const [customers, setCustomers] = useState<PolicyCustomerOption[]>([]);
  const [loadingCustomers, setLoadingCustomers] = useState(true);

  useEffect(() => {
    async function loadCustomers() {
      try {
        const response = await api.get<PolicyCustomerOption[]>("/admin/users/customers");
        setCustomers(response.data);
      } finally {
        setLoadingCustomers(false);
      }
    }

    void loadCustomers();
  }, []);

  async function handleSubmit(payload: PolicyFormValues) {
    await api.post("/policies", {
      insuranceType: payload.insuranceType,
      customerId: payload.customerId,
      coverageAmount: Number(payload.coverageAmount),
      premiumAmount: Number(payload.premiumAmount),
      effectiveDate: payload.effectiveDate,
      expiryDate: payload.expiryDate
    });

    router.push("/policies");
  }

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["AGENT", "ADMIN"]}>
        <PageShell>
          <SectionHeader
            title="Create Policy"
            subtitle="Create a policy for an existing customer."
          />

          <PolicyForm
            onSubmit={handleSubmit}
            customers={customers}
            loadingCustomers={loadingCustomers}
            submitLabel="Create Policy"
          />
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}