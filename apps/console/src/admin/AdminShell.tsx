import { EmptyState, PageHeader } from '@d3cloud/ui';

// Operator console: users, apps, access, groups, audit, keys, settings (Phases 3 and 4).
export default function AdminShell() {
  return (
    <main className="shell">
      <PageHeader title="Console" description="People, apps and the roles they hold in each." />
      <EmptyState kind="empty" size="page" headingLevel={2} heading="The console arrives in Phase 3">
        Users, apps and grants are managed here once registration is built.
      </EmptyState>
    </main>
  );
}
