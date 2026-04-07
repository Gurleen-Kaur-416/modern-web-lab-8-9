"use client";

import { Shield, Users, Briefcase, UserCheck, FileText } from "lucide-react";

interface RoleSummaryCardProps {
  role: string;
  count: number;
  description?: string;
}

const roleConfig: Record<
  string,
  {
    label: string;
    icon: any;
    color: string;
    bg: string;
  }
> = {
  ADMIN: {
    label: "Administrators",
    icon: Shield,
    color: "text-red-600",
    bg: "bg-red-50"
  },
  AGENT: {
    label: "Insurance Agents",
    icon: Briefcase,
    color: "text-blue-600",
    bg: "bg-blue-50"
  },
  CUSTOMER: {
    label: "Customers",
    icon: Users,
    color: "text-green-600",
    bg: "bg-green-50"
  },
  UNDERWRITER: {
    label: "Underwriters",
    icon: UserCheck,
    color: "text-purple-600",
    bg: "bg-purple-50"
  },
  CLAIMS_ADJUSTER: {
    label: "Claims Adjusters",
    icon: FileText,
    color: "text-orange-600",
    bg: "bg-orange-50"
  }
};

export default function RoleSummaryCard({
  role,
  count,
  description
}: RoleSummaryCardProps) {
  const config = roleConfig[role] || {
    label: role,
    icon: Users,
    color: "text-gray-600",
    bg: "bg-gray-50"
  };

  const Icon = config.icon;

  return (
    <div
      className={`rounded-2xl shadow-sm border p-5 flex items-center justify-between ${config.bg} hover:shadow-md transition`}
    >
      <div className="flex items-center gap-4">
        <div className={`p-3 rounded-xl bg-white shadow ${config.color}`}>
          <Icon size={22} />
        </div>

        <div>
          <p className="text-sm text-gray-500">{config.label}</p>
          <p className="text-2xl font-semibold text-gray-900">{count}</p>

          {description && (
            <p className="text-xs text-gray-400 mt-1">{description}</p>
          )}
        </div>
      </div>
    </div>
  );
}