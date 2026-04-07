import type { ReactNode } from "react";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

interface PageShellProps {
  children: ReactNode;
}

export default function PageShell({ children }: PageShellProps) {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="content-shell">
        <Topbar />
        <section className="content-panel">{children}</section>
      </main>
    </div>
  );
}