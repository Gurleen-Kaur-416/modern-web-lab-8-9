"use client";

import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { createUser, updateUser } from "@/lib/api";
import { useRouter } from "next/navigation";
import Alert from "@/components/feedback/Alert";

const userSchema = z.object({
  fullName: z.string().min(3, "Full name is required"),
  email: z.string().email("Invalid email"),
  password: z.string().optional(),
  roles: z.array(z.string()).min(1, "At least one role is required"),
  status: z.enum(["ACTIVE", "INACTIVE"])
});

type UserFormData = z.infer<typeof userSchema>;

interface UserFormProps {
  initialData?: any;
  isEdit?: boolean;
}

const roleOptions = [
  "ADMIN",
  "AGENT",
  "CUSTOMER",
  "UNDERWRITER",
  "CLAIMS_ADJUSTER"
];

export default function UserForm({ initialData, isEdit = false }: UserFormProps) {
  const router = useRouter();

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors, isSubmitting }
  } = useForm<UserFormData>({
    resolver: zodResolver(userSchema),
    defaultValues: {
      fullName: initialData?.fullName || "",
      email: initialData?.email || "",
      password: "",
      roles: initialData?.roles || [],
      status: initialData?.status || "ACTIVE"
    }
  });

  const selectedRoles = watch("roles");

  const toggleRole = (role: string) => {
    const current = selectedRoles || [];
    if (current.includes(role)) {
      setValue("roles", current.filter((r) => r !== role));
    } else {
      setValue("roles", [...current, role]);
    }
  };

  const onSubmit = async (data: UserFormData) => {
    try {
      if (isEdit) {
        await updateUser(initialData._id, data);
      } else {
        await createUser(data);
      }

      router.push("/admin/users");
    } catch (error: any) {
      console.error(error);
      alert("Failed to save user");
    }
  };

  return (
    <form
      onSubmit={handleSubmit(onSubmit)}
      className="bg-white p-6 rounded-2xl shadow-md border space-y-6"
    >
      <h2 className="text-xl font-semibold">
        {isEdit ? "Edit User" : "Create User"}
      </h2>

      {/* FULL NAME */}
      <div>
        <label className="block text-sm font-medium">Full Name</label>
        <input
          {...register("fullName")}
          className="mt-1 w-full border rounded-lg px-3 py-2"
        />
        {errors.fullName && (
          <p className="text-red-500 text-sm">{errors.fullName.message}</p>
        )}
      </div>

      {/* EMAIL */}
      <div>
        <label className="block text-sm font-medium">Email</label>
        <input
          {...register("email")}
          className="mt-1 w-full border rounded-lg px-3 py-2"
        />
        {errors.email && (
          <p className="text-red-500 text-sm">{errors.email.message}</p>
        )}
      </div>

      {/* PASSWORD */}
      {!isEdit && (
        <div>
          <label className="block text-sm font-medium">Password</label>
          <input
            type="password"
            {...register("password")}
            className="mt-1 w-full border rounded-lg px-3 py-2"
          />
        </div>
      )}

      {/* ROLES */}
      <div>
        <label className="block text-sm font-medium mb-2">Roles</label>
        <div className="flex flex-wrap gap-3">
          {roleOptions.map((role) => (
            <button
              type="button"
              key={role}
              onClick={() => toggleRole(role)}
              className={`px-4 py-2 rounded-lg border ${
                selectedRoles?.includes(role)
                  ? "bg-blue-600 text-white"
                  : "bg-gray-100"
              }`}
            >
              {role}
            </button>
          ))}
        </div>
        {errors.roles && (
          <p className="text-red-500 text-sm">{errors.roles.message}</p>
        )}
      </div>

      {/* STATUS */}
      <div>
        <label className="block text-sm font-medium">Status</label>
        <select
          {...register("status")}
          className="mt-1 w-full border rounded-lg px-3 py-2"
        >
          <option value="ACTIVE">Active</option>
          <option value="INACTIVE">Inactive</option>
        </select>
      </div>

      {/* ACTIONS */}
      <div className="flex justify-end gap-3">
        <button
          type="button"
          onClick={() => router.back()}
          className="px-4 py-2 border rounded-lg"
        >
          Cancel
        </button>

        <button
          type="submit"
          disabled={isSubmitting}
          className="px-5 py-2 bg-blue-600 text-white rounded-lg"
        >
          {isSubmitting ? "Saving..." : isEdit ? "Update User" : "Create User"}
        </button>
      </div>
    </form>
  );
}