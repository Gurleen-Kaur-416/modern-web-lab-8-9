"use client";

import { useState, type FormEvent } from "react";

interface RoleAssignmentFormProps {
  availableRoles: string[];
  currentRoles: string[];
  onSubmit: (roles: string[]) => Promise<void>;
}

export default function RoleAssignmentForm({
  availableRoles,
  currentRoles,
  onSubmit
}: RoleAssignmentFormProps) {
  const [selectedRoles, setSelectedRoles] = useState<string[]>(currentRoles);

  function toggleRole(role: string) {
    setSelectedRoles((prev) =>
      prev.includes(role) ? prev.filter((item) => item !== role) : [...prev, role]
    );
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onSubmit(selectedRoles);
  }

  return (
    <form onSubmit={handleSubmit} className="form-grid">
      <div className="full-span">
        <label>Assigned Roles</label>
        <div className="checkbox-grid">
          {availableRoles.map((role) => (
            <label key={role} className="checkbox-card">
              <input
                type="checkbox"
                checked={selectedRoles.includes(role)}
                onChange={() => toggleRole(role)}
              />
              <span>{role}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="full-span">
        <button className="btn btn-primary" type="submit">
          Update roles
        </button>
      </div>
    </form>
  );
}