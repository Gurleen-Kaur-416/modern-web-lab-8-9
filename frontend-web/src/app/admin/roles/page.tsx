"use client";

import { useEffect, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import DataTable, { type DataTableColumn } from "@/components/tables/DataTable";
import type { Role } from "@/types/role";
import { apiRequest } from "@/lib/api";

export default function AdminRolesPage() {
  const [roles, setRoles] = useState<Role[]>([]);

  useEffect(() => {
    async function load() {
      const response = await apiRequest<Role[]>("/admin/rbac/roles");
      setRoles(response.data);
    }

    void load();
  }, []);

  const columns: DataTableColumn<Role>[] = [
    { key: "name", label: "Role", render: (row) => row.name },
    { key: "permissions", label: "Permissions", render: (row) => row.permissions.join(", ") }
  ];

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["ADMIN"]}>
        <PageShell>
          <SectionHeader title="Roles" subtitle="Role definitions and mapped permissions." />
          <DataTable columns={columns} data={roles} rowKey={(row) => row._id} />
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}