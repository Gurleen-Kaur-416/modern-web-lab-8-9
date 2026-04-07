"use client";

import { useEffect, useState } from "react";
import ProtectedRoute from "@/components/guards/ProtectedRoute";
import RoleGuard from "@/components/guards/RoleGuard";
import PageShell from "@/components/layout/PageShell";
import SectionHeader from "@/components/layout/SectionHeader";
import RoleAssignmentForm from "@/components/forms/RoleAssignmentForm";
import { apiRequest } from "@/lib/api";
import type { User } from "@/types/user";
import type { Role } from "@/types/role";

export default function AdminRbacPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [selectedUserId, setSelectedUserId] = useState("");

  useEffect(() => {
    async function load() {
      const [usersResponse, rolesResponse] = await Promise.all([
        apiRequest<User[]>("/admin/users"),
        apiRequest<Role[]>("/admin/rbac/roles")
      ]);

      setUsers(usersResponse.data);
      setRoles(rolesResponse.data);

      if (usersResponse.data.length > 0) {
        setSelectedUserId(usersResponse.data[0]._id);
      }
    }

    void load();
  }, []);

  const selectedUser = users.find((user) => user._id === selectedUserId);

  async function handleRoleUpdate(nextRoles: string[]) {
    if (!selectedUserId) return;

    await apiRequest(`/admin/rbac/users/${selectedUserId}/roles`, {
      method: "PUT",
      body: { roles: nextRoles }
    });

    const refreshedUsers = await apiRequest<User[]>("/admin/users");
    setUsers(refreshedUsers.data);
  }

  return (
    <ProtectedRoute>
      <RoleGuard allowedRoles={["ADMIN"]}>
        <PageShell>
          <SectionHeader title="RBAC Management" subtitle="Assign and manage user roles centrally." />

          <div className="panel">
            <label>Select User</label>
            <select value={selectedUserId} onChange={(e) => setSelectedUserId(e.target.value)}>
              {users.map((user) => (
                <option key={user._id} value={user._id}>
                  {user.username}
                </option>
              ))}
            </select>
          </div>

          {selectedUser ? (
            <RoleAssignmentForm
              availableRoles={roles.map((role) => role.name)}
              currentRoles={selectedUser.roles}
              onSubmit={handleRoleUpdate}
            />
          ) : null}
        </PageShell>
      </RoleGuard>
    </ProtectedRoute>
  );
}