import type { ReactNode } from "react";

interface DashboardGridProps {
  children: ReactNode;
}

export default function DashboardGrid({ children }: DashboardGridProps) {
  return <div className="stats-grid">{children}</div>;
}