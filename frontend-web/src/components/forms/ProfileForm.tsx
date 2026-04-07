"use client";

import { useState, type FormEvent } from "react";
import type { UserProfile } from "@/types/user";

interface ProfileFormProps {
  initialValue: UserProfile;
  onSubmit: (payload: Partial<UserProfile>) => Promise<void>;
}

export default function ProfileForm({ initialValue, onSubmit }: ProfileFormProps) {
  const [form, setForm] = useState<Partial<UserProfile>>(initialValue);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await onSubmit(form);
  }

  return (
    <form className="form-grid" onSubmit={handleSubmit}>
      <div>
        <label>First Name</label>
        <input
          value={form.firstName ?? ""}
          onChange={(e) => setForm({ ...form, firstName: e.target.value })}
        />
      </div>

      <div>
        <label>Last Name</label>
        <input
          value={form.lastName ?? ""}
          onChange={(e) => setForm({ ...form, lastName: e.target.value })}
        />
      </div>

      <div>
        <label>Email</label>
        <input
          value={form.email ?? ""}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
        />
      </div>

      <div>
        <label>Phone</label>
        <input
          value={form.phone ?? ""}
          onChange={(e) => setForm({ ...form, phone: e.target.value })}
        />
      </div>

      <div>
        <label>City</label>
        <input
          value={form.city ?? ""}
          onChange={(e) => setForm({ ...form, city: e.target.value })}
        />
      </div>

      <div>
        <label>Country</label>
        <input
          value={form.country ?? ""}
          onChange={(e) => setForm({ ...form, country: e.target.value })}
        />
      </div>

      <div className="full-span">
        <button className="btn btn-primary" type="submit">
          Save profile changes
        </button>
      </div>
    </form>
  );
}