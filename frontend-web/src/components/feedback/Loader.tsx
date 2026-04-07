interface LoaderProps {
  label?: string;
}

export default function Loader({ label = "Loading..." }: LoaderProps) {
  return (
    <div className="center-screen">
      <div className="panel small-panel">
        <div className="loader-spinner" />
        <p>{label}</p>
      </div>
    </div>
  );
}