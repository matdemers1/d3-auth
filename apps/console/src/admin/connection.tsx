import { Alert, Badge, DescriptionItem, DescriptionList, IconButton, Link, Section, Stack, Tooltip } from '@d3cloud/ui';
import { Check, Copy } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { Connection, PresetSheet, SheetAction, SheetRow } from '../api';
import { icon } from '../shared/icons';

// The connection sheet (C-6, REQ-142): every value an app needs, each with a copy button and one
// line of why. The rows come from the server, which builds them from the provider's own
// configuration — nothing here knows what ES256 is.
//
// Composed from DescriptionList, `code`, IconButton and Tooltip. If a second app needs a copyable
// value, this is the CopyField candidate for the design system.

const ACTION: Record<SheetAction, { text: string; tone: 'attention' | 'neutral' }> = {
  set: { text: 'Set', tone: 'attention' },
  on: { text: 'Turn on', tone: 'attention' },
  off: { text: 'Turn off', tone: 'attention' },
  leave: { text: 'Leave as is', tone: 'neutral' },
};

/** Selects the text of an element, for when the clipboard cannot be written to. */
function selectText(element: HTMLElement | null): void {
  const selection = window.getSelection();
  if (!element || !selection) return;
  const range = document.createRange();
  range.selectNodeContents(element);
  selection.removeAllRanges();
  selection.addRange(range);
}

/**
 * One value in monospace and a button that copies it. "Copied" is said in text beside the button
 * and announced politely; where the clipboard is not available (plain http on a real host, an old
 * browser) the value is selected instead, and the text says how to copy it.
 */
export function CopyValue({ label, value, copyable = true }: { label: string; value: string; copyable?: boolean }) {
  const code = useRef<HTMLElement>(null);
  const [said, setSaid] = useState<'' | 'copied' | 'selected'>('');

  useEffect(() => {
    if (said === '') return undefined;
    const timer = window.setTimeout(() => {
      setSaid('');
    }, 4000);
    return () => {
      window.clearTimeout(timer);
    };
  }, [said]);

  async function copy() {
    try {
      // Typed as always present; it is not, outside a secure context.
      const { clipboard } = navigator as { clipboard?: Clipboard };
      if (!clipboard) throw new Error('no clipboard');
      await clipboard.writeText(value);
      setSaid('copied');
    } catch {
      selectText(code.current);
      setSaid('selected');
    }
  }

  return (
    <span className="sheet-value">
      <code ref={code}>{value}</code>
      {copyable ? (
        <span className="sheet-copy">
          <Tooltip content={`Copy ${label}`}>
            <IconButton size="sm" icon={icon(said === 'copied' ? Check : Copy)} label={`Copy ${label}`} onClick={() => void copy()} />
          </Tooltip>
          <span className="sheet-said" role="status">
            {said === 'copied' ? 'Copied' : said === 'selected' ? 'Selected — copy it with your keyboard' : ''}
          </span>
        </span>
      ) : null}
    </span>
  );
}

function RowValue({ row, secretCopyable }: { row: SheetRow; secretCopyable: boolean }) {
  const copyable = !row.secret || secretCopyable;
  if (Array.isArray(row.value)) {
    return (
      <Stack gap="4">
        {row.value.map((value) => (
          <CopyValue key={value} label={`${row.label} ${value}`} value={value} />
        ))}
      </Stack>
    );
  }
  if (row.value === null) return null;
  // A field to leave alone shows what it should already say; there is nothing to paste.
  return <CopyValue label={row.label} value={row.value} copyable={copyable && row.action !== 'leave'} />;
}

/** The rows, as terms and values. `secretCopyable` only where the secret was just made. */
export function SheetRows({ rows, secretCopyable = false, label }: { rows: SheetRow[]; secretCopyable?: boolean; label: string }) {
  return (
    <DescriptionList aria-label={label}>
      {rows.map((row) => (
        <DescriptionItem key={row.id} term={row.label}>
          <Stack gap="4" className="sheet-row">
            {row.action ? (
              <span>
                <Badge size="sm" tone={ACTION[row.action].tone}>
                  {ACTION[row.action].text}
                </Badge>
              </span>
            ) : null}
            <RowValue row={row} secretCopyable={secretCopyable} />
            {row.why ? <span className="sheet-why">{row.why}</span> : null}
          </Stack>
        </DescriptionItem>
      ))}
    </DescriptionList>
  );
}

/** The other app's settings screen, in its order and its words. */
export function PresetSheetSection({
  sheet,
  secretCopyable = false,
  title = `In ${sheet.name}`,
}: {
  sheet: PresetSheet;
  secretCopyable?: boolean;
  title?: string;
}) {
  return (
    <Section
      title={title}
      description={`Open ${sheet.where} in ${sheet.name} and go down the page. Each field as ${sheet.name} labels it, in the order it shows them — checked against ${sheet.name} on ${sheet.checked}.`}
      actions={
        <Link variant="standalone" href={sheet.docsUrl} target="_blank" rel="noreferrer">
          {sheet.name}’s OAuth guide
        </Link>
      }
    >
      {sheet.steps.length > 0 || sheet.cautions.length > 0 ? (
        <Alert tone="info" title="Before people sign in">
          <ul>
            {[...sheet.steps, ...sheet.cautions].map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </Alert>
      ) : null}
      <SheetRows rows={sheet.rows} secretCopyable={secretCopyable} label={`${sheet.name} settings`} />
    </Section>
  );
}

/** Every value any app needs. */
export function ConnectionSection({
  connection,
  title = 'Connection details',
  description = 'What any app needs to sign people in here. Each value is taken from how D3 Auth is set up, so it is always current.',
  secretCopyable = false,
  actions,
  id,
}: {
  connection: Connection;
  title?: string;
  description?: React.ReactNode;
  secretCopyable?: boolean;
  actions?: React.ReactNode;
  id?: string;
}) {
  return (
    <Section title={title} description={description} {...(actions ? { actions } : {})} {...(id ? { id } : {})}>
      <SheetRows rows={connection.rows} secretCopyable={secretCopyable} label={title} />
    </Section>
  );
}
