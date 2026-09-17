import { Alert, Button, Card, DataList, DataListRow, DescriptionItem, DescriptionList, EmptyState, Section, Skeleton } from '@d3cloud/ui';
import { icon } from './icons';
import { ShieldHalf } from 'lucide-react';

// The states every page has besides "loaded" (Page states pattern). Each renders inside the page's
// own `Page`, under its real header, where the content will be.

const WIDTHS = ['9rem', '7rem', '11rem', '8rem', '10rem', '12rem'];
const width = (i: number): string => WIDTHS[i % WIDTHS.length] ?? '8rem';

/** Skeleton rows the shape of rows, in the card the list will fill. */
export function RowsSkeleton({ rows = 4, leading = false }: { rows?: number; leading?: boolean }) {
  return (
    <Card>
      <DataList aria-hidden="true">
        {Array.from({ length: rows }, (_, i) => (
          <DataListRow
            key={i}
            {...(leading ? { leading: <Skeleton variant="circle" width={24} height={24} /> } : {})}
            title={<Skeleton variant="text" width={width(i)} />}
            description={<Skeleton variant="text" width={width(i + 3)} />}
            meta={<Skeleton variant="text" width="5rem" />}
          />
        ))}
      </DataList>
    </Card>
  );
}

/** A Section whose title is known and whose facts are not yet. */
export function FactsSkeleton({ title, rows = 4 }: { title: string; rows?: number }) {
  return (
    <Section title={title} aria-hidden="true">
      <DescriptionList>
        {Array.from({ length: rows }, (_, i) => (
          <DescriptionItem key={i} term={<Skeleton variant="text" width={width(i)} />}>
            <Skeleton variant="text" width={width(i + 2)} />
          </DescriptionItem>
        ))}
      </DescriptionList>
    </Section>
  );
}

/** The request failed: say what, say what still works, and offer the retry. */
export function LoadFailed({ what, message, onRetry }: { what: string; message: string; onRetry: () => void }) {
  return (
    <Alert
      tone="danger"
      title={`${what} could not load`}
      actions={
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      }
    >
      {message} Signing in to apps is not affected — this is the console, not the provider.
    </Alert>
  );
}

/** The server refused. Say so, and say who can change it. */
export function Denied({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <EmptyState kind="no-access" headingLevel={2} heading={heading} icon={icon(ShieldHalf, 24)}>
      {children}
    </EmptyState>
  );
}
