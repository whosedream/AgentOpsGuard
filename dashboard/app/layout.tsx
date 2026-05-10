import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AgentOps Guard",
  description: "Agent tracing, evaluation, and security gateway",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
