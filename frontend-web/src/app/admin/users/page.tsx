"use client";

import { useEffect, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import DataTable, { type DataTableColumn } from "@/components/tables/DataTable";
import StatusBadge from "@/components/tables/StatusBadge";
import { apiRequest } from "@/lib/api";
import type { User } from "@/types/user";

export default function AdminUsersPage() {
  const [users, setUsers] = useState<User[]>([]);

  useEffect(() => {
    async function load() {
      const response = await apiRequest<User[]>("/admin/users");
      setUsers(response.data);
    }

    void load();
  }, []);

  const columns: DataTableColumn<User>[] = [
    { key: "username", label: "Username", render: (row) => row.username },
    { key: "fullName", label: "Full Name", render: (row) => `${row.profile.firstName} ${row.profile.lastName}` },
    { key: "roles", label: "Roles", render: (row) => row.roles.join(", ") },
    { key: "accountStatus", label: "Status", render: (row) => <StatusBadge value={row.accountStatus} /> }
  ];

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["ADMIN"]}>
        <PageShell>
          <SectionHeader title="Admin Users" subtitle="Centralized user account administration." />
          <DataTable columns={columns} data={users} rowKey={(row) => row._id} />
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}