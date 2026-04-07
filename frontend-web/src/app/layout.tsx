import type { Metadata } from "next";
import "./globals.css";
import "@/styles/theme.css";
import { AuthProvider } from "@/context/AuthContext";
import { APP_NAME } from "@/lib/constants";

export const metadata: Metadata = {
  title: APP_NAME,
  description: "Secure insurance platform with JWT, RBAC, and professional operations flows"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}