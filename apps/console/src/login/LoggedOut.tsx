import { EmptyState, Link } from '@d3cloud/ui';

// I-8: where a logout lands when the app did not register a post-logout URL.
export function LoggedOut() {
  return (
    <main className="shell shell--narrow">
      <EmptyState kind="empty" size="page" headingLevel={2} heading="You are signed out">
        You can close this tab, or sign in again from the app you were using.
      </EmptyState>
      <p>
        <Link variant="standalone" href="/signin">
          Sign in again
        </Link>
      </p>
    </main>
  );
}
