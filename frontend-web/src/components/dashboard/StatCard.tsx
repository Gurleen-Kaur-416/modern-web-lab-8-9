interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
}

export default function StatCard({ title, value, subtitle }: StatCardProps) {
  return (
    <div className="stat-card">
      <div className="stat-value">{value}</div>
      <div className="stat-title">{title}</div>
      {subtitle ? <div className="stat-subtitle">{subtitle}</div> : null}
    </div>
  );
}