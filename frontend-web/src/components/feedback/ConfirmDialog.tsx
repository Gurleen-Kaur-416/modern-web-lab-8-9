interface ConfirmDialogProps {
  title: string;
  description: string;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({
  title,
  description,
  onConfirm,
  onCancel
}: ConfirmDialogProps) {
  return (
    <div className="panel">
      <h3>{title}</h3>
      <p>{description}</p>
      <div className="actions-row">
        <button className="btn btn-secondary" onClick={onCancel}>
          Cancel
        </button>
        <button className="btn btn-primary" onClick={onConfirm}>
          Confirm
        </button>
      </div>
    </div>
  );
}