import { Alert } from '@d3cloud/ui';
import { api, type Person } from '../api';
import { Confirm } from '../shared/Confirm';

// What People and a person's own page both do to an account: suspend and let back in (reversible,
// so they act at once and say what happened), and reset (irreversible, so it asks in a Modal).

export interface ResetResult {
  email: string;
  url: string;
  delivered: boolean;
}

type Who = Pick<Person, 'id' | 'displayName' | 'email' | 'kind' | 'status'>;

export const firstName = (person: Pick<Person, 'displayName'>): string => person.displayName.split(' ')[0] ?? person.displayName;

export const suspend = (person: Who): Promise<unknown> => api.post(`/api/admin/people/${person.id}/suspend`);
export const reactivate = (person: Who): Promise<unknown> => api.post(`/api/admin/people/${person.id}/reactivate`);
export const changeKind = (person: Who): Promise<unknown> =>
  api.post(`/api/admin/people/${person.id}/kind`, { kind: person.kind === 'admin' ? 'guest' : 'admin' });

export async function reset(person: Who): Promise<ResetResult> {
  const answer = await api.post<{ url?: string; mail?: { delivered: boolean } }>(`/api/admin/people/${person.id}/reset`);
  return { email: person.email, url: answer.url ?? '', delivered: answer.mail?.delivered ?? false };
}

/** `open` is driven by whoever offers the action — a row's menu, or the danger zone's button. */
export function ConfirmReset({
  person,
  open,
  onOpenChange,
  trigger,
  onDone,
}: {
  person: Who;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  trigger?: React.ReactNode;
  onDone: (result: ResetResult) => void;
}) {
  return (
    <Confirm
      {...(open === undefined ? {} : { open })}
      {...(onOpenChange ? { onOpenChange } : {})}
      {...(trigger ? { trigger } : {})}
      title={`Reset ${person.displayName}’s account?`}
      description={`Their password, passkeys and authenticator apps are removed, and they are signed out everywhere. They set the account up again from a link that works once — the same account, with the same access. This cannot be undone.`}
      confirm="Reset account"
      cancel={`Keep ${firstName(person)}’s sign-in`}
      onConfirm={async () => {
        onDone(await reset(person));
      }}
    />
  );
}

/** Mail is the log driver in development, and down sometimes in production: the link is the fallback (REQ-108). */
export function ResetOutcome({ result }: { result: ResetResult }) {
  return result.delivered ? (
    <Alert tone="success" dynamic title={`A set-up-again link was emailed to ${result.email}`}>
      It works once and expires in two hours. Their account, and everything it can reach, is unchanged.
    </Alert>
  ) : (
    <Alert tone="warning" dynamic title={`The account was reset, but the email to ${result.email} did not send`}>
      <p>Send them this link yourself. It works once and expires in two hours.</p>
      <code>{result.url}</code>
    </Alert>
  );
}
