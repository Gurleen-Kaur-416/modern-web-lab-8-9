interface StatusBadgeProps {
  value: string;
}

export default function StatusBadge({ value }: StatusBadgeProps) {
  return <span className={`status-badge status-${value.toLowerCase().replace(/\s+/g, "-")}`}>{value}</span>;
}