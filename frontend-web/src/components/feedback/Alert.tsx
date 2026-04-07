interface AlertProps {
  variant?: "info" | "success" | "error";
  message: string;
}

export default function Alert({ variant = "info", message }: AlertProps) {
  return <div className={`alert alert-${variant}`}>{message}</div>;
}