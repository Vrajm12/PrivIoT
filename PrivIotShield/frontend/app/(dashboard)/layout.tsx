import React from "react";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopContextBar } from "@/components/layout/TopContextBar";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar />
      <div className="flex-1 ml-56 flex flex-col min-w-0">
        <TopContextBar />
        <main className="flex-1 p-6 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
