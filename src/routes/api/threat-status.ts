import { createFileRoute } from "@tanstack/react-router";
import { getThreatDb } from "@/lib/threat-feed.server";

export const Route = createFileRoute("/api/threat-status")({
  server: {
    handlers: {
      GET: async () => {
        const d = await getThreatDb();
        return Response.json({ total: d.total, updatedAt: d.updatedAt });
      },
    },
  },
});
