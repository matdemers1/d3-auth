import { EmptyState, Spinner } from '@d3cloud/ui';
import { lazy, Suspense } from 'react';
import { surfaceFor } from './surface';

const LoginShell = lazy(() => import('./login/LoginShell'));
const AccountShell = lazy(() => import('./account/AccountShell'));
const AdminShell = lazy(() => import('./admin/AdminShell'));

export function App() {
  const surface = surfaceFor(window.location.pathname);

  return (
    <Suspense fallback={<div className="shell-loading"><Spinner size="lg" label="Loading" /></div>}>
      {surface === 'login' && <LoginShell />}
      {surface === 'account' && <AccountShell />}
      {surface === 'admin' && <AdminShell />}
      {surface === 'server-rendered' && null}
      {surface === 'not-found' && (
        <main className="shell shell--narrow">
          <EmptyState kind="error" size="page" headingLevel={2} heading="There is nothing at this address">
            Check the link you followed.
          </EmptyState>
        </main>
      )}
    </Suspense>
  );
}
