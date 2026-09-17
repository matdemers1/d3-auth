import { Alert, Button, Modal } from '@d3cloud/ui';
import { useState } from 'react';
import { messageOf } from './load';

// Asking before something that cannot be taken back (Confirmation pattern): a `Modal destructive`
// opened by a `danger-ghost` button that names the object. The scrim does not close it, focus
// lands on the panel rather than the destructive button, and the button says the same verb and
// object as the title.
//
// This replaces the console's two-click inline confirms ("Reset" → "Yes, reset their account"),
// which moved under the pointer so a double-click was a confirmation nobody read.

export interface ConfirmProps {
  /** The trigger, when the modal opens itself. Omit and pass `open` to open it from a menu item. */
  trigger?: React.ReactNode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  /** The action and the object, as a question: "Delete Editors?" */
  title: string;
  /** What goes, what stays, and whether it can be undone. */
  description: string;
  /** Same verb and object as the title: "Delete Editors". */
  confirm: string;
  /** What keeping it means: "Keep Editors", or "Cancel". */
  cancel?: string;
  /** Resolves when it is done; a rejection keeps the dialog open and says why. */
  onConfirm: () => Promise<void>;
  children?: React.ReactNode;
}

export function Confirm({ trigger, open, onOpenChange, title, description, confirm, cancel = 'Cancel', onConfirm, children }: ConfirmProps) {
  const [own, setOwn] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | undefined>();
  const isOpen = open ?? own;
  const setOpen = (next: boolean) => {
    if (!next) setProblem(undefined);
    setOwn(next);
    onOpenChange?.(next);
  };

  async function go() {
    setBusy(true);
    setProblem(undefined);
    try {
      await onConfirm();
      setOpen(false);
    } catch (err) {
      setProblem(messageOf(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      destructive
      open={isOpen}
      onOpenChange={setOpen}
      {...(trigger ? { trigger } : {})}
      title={title}
      description={description}
      footer={
        <>
          <Button
            disabled={busy}
            onClick={() => {
              setOpen(false);
            }}
          >
            {cancel}
          </Button>
          <Button variant="danger" loading={busy} onClick={() => void go()}>
            {confirm}
          </Button>
        </>
      }
    >
      {problem ? (
        <Alert tone="danger" dynamic title="That did not work">
          {problem}
        </Alert>
      ) : null}
      {children}
    </Modal>
  );
}
