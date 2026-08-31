import React from "react";
import { cn } from "@/lib/utils";

interface Column<T> {
  header: string;
  accessorKey?: keyof T;
  cell?: (item: T) => React.ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (item: T) => void;
  isLoading?: boolean;
  emptyMessage?: string;
}

export function DataTable<T extends { id: number | string }>({
  columns,
  data,
  onRowClick,
  isLoading = false,
  emptyMessage = "No records found in active scope."
}: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="border border-surface-border rounded-lg bg-surface-primary p-8 text-center text-xs text-text-muted font-mono">
        <span className="inline-block w-4 h-4 border-2 border-accent border-t-transparent rounded-full animate-spin mr-2" />
        LOADING OPERATIONAL DATA...
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="border border-surface-border rounded-lg bg-surface-primary p-8 text-center text-xs text-text-muted font-mono">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto border border-surface-border rounded-lg bg-surface-primary">
      <table className="w-full text-left text-xs">
        <thead className="bg-surface-elevated text-text-secondary font-mono uppercase tracking-wider border-b border-surface-border">
          <tr>
            {columns.map((col, idx) => (
              <th key={idx} className={cn("py-2.5 px-3 font-semibold", col.className)}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-border/60">
          {data.map((row) => (
            <tr
              key={row.id}
              onClick={() => onRowClick && onRowClick(row)}
              className={cn(
                "hover:bg-surface-elevated/70 transition-colors group",
                onRowClick && "cursor-pointer"
              )}
            >
              {columns.map((col, idx) => (
                <td key={idx} className={cn("py-2.5 px-3 text-text-primary", col.className)}>
                  {col.cell ? col.cell(row) : col.accessorKey ? String(row[col.accessorKey] ?? "") : null}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
