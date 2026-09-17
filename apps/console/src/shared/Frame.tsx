import {
  AccountMenu,
  AppShell,
  AppShellBrand,
  MenuItem,
  MenuSeparator,
  SideNav,
  SideNavGroup,
  SideNavItem,
  ThemeSwitch,
} from '@d3cloud/ui';
import {
  AppWindow,
  ArrowLeftRight,
  House,
  KeyRound,
  LayoutGrid,
  LockKeyhole,
  LogOut,
  MonitorSmartphone,
  ScrollText,
  Settings,
  ShieldHalf,
  ShieldCheck,
  UserRound,
  Users,
  UsersRound,
} from 'lucide-react';
import type { Me } from '../api';
import { SIGN_OUT_HREF } from '../signout';
import { icon } from './icons';
import { KIND_LABEL, MeProvider } from './me';

// The one frame every signed-in page sits in (App frame pattern): the sidebar for the places
// people go every day, the account menu for who is signed in and the things set up once.
//
// Plain links, not a router: each screen is its own page load, so the back button does what a back
// button should and nothing has to remember where it came from.

export type AdminPlace = 'home' | 'people' | 'groups' | 'apps' | 'keys' | 'audit' | 'settings' | 'transfer';
export type AccountPlace = 'apps' | 'profile' | 'password' | 'security' | 'sessions';

const isOwner = (me: Me | undefined): boolean => me?.kind === 'owner';
const isAdmin = (me: Me | undefined): boolean => me?.kind === 'owner' || me?.kind === 'admin';

/**
 * Apps and Keys are the owner's. Leaving them out for an admin keeps the list to what they can use
 * — it is tidiness, not the lock: the server refuses, and the page says so.
 */
function AdminNav({ current, me }: { current: AdminPlace; me: Me }) {
  return (
    <SideNav aria-label="Console">
      <SideNavItem href="/admin" icon={icon(House)} label="Home" current={current === 'home'} />
      <SideNavGroup title="Directory">
        <SideNavItem href="/admin/people" icon={icon(Users)} label="People" current={current === 'people'} />
        <SideNavItem href="/admin/groups" icon={icon(UsersRound)} label="Groups" current={current === 'groups'} />
        {isOwner(me) ? <SideNavItem href="/admin/apps" icon={icon(AppWindow)} label="Apps" current={current === 'apps'} /> : null}
      </SideNavGroup>
      <SideNavGroup title="Trust">
        {isOwner(me) ? <SideNavItem href="/admin/keys" icon={icon(KeyRound)} label="Keys" current={current === 'keys'} /> : null}
        <SideNavItem href="/admin/audit" icon={icon(ScrollText)} label="Audit" current={current === 'audit'} />
      </SideNavGroup>
    </SideNav>
  );
}

function AccountNav({ current }: { current: AccountPlace }) {
  return (
    <SideNav aria-label="Your account">
      <SideNavItem href="/account" icon={icon(LayoutGrid)} label="Your apps" current={current === 'apps'} />
      <SideNavGroup title="Account">
        <SideNavItem href="/account/profile" icon={icon(UserRound)} label="Profile" current={current === 'profile'} />
        <SideNavItem href="/account/password" icon={icon(LockKeyhole)} label="Password" current={current === 'password'} />
        <SideNavItem href="/account/security" icon={icon(ShieldCheck)} label="Security" current={current === 'security'} />
        <SideNavItem href="/account/sessions" icon={icon(MonitorSmartphone)} label="Sessions" current={current === 'sessions'} />
      </SideNavGroup>
    </SideNav>
  );
}

/**
 * Who is signed in, then the places set up once, then the theme, then sign-out — last, on every
 * page, in the same place (ASVS 7.4.4). The provider asks "Sign out of D3 Auth?" before it acts, so
 * a stray click costs a "Stay signed in", and signing out lands on /signed-out (ADR-005).
 */
function Account({ me, area }: { me: Me; area: 'admin' | 'account' }) {
  return (
    <AccountMenu name={me.displayName} detail={`${KIND_LABEL[me.kind]} · ${me.email}`}>
      {area === 'admin' ? (
        <>
          <MenuItem asChild icon={icon(UserRound)}>
            <a href="/account">Your account</a>
          </MenuItem>
          <MenuItem asChild icon={icon(ShieldCheck)}>
            <a href="/account/security">Security</a>
          </MenuItem>
          {isOwner(me) ? (
            <>
              <MenuSeparator />
              <MenuItem asChild icon={icon(Settings)}>
                <a href="/admin/settings">Settings</a>
              </MenuItem>
              <MenuItem asChild icon={icon(ArrowLeftRight)}>
                <a href="/admin/transfer">Export and import</a>
              </MenuItem>
            </>
          ) : null}
        </>
      ) : isAdmin(me) ? (
        <MenuItem asChild icon={icon(ShieldHalf)}>
          <a href="/admin">Open the console</a>
        </MenuItem>
      ) : null}
      {area === 'admin' || isAdmin(me) ? <MenuSeparator /> : null}
      <ThemeSwitch />
      <MenuSeparator />
      <MenuItem asChild tone="danger" icon={icon(LogOut)}>
        <a href={SIGN_OUT_HREF}>Sign out</a>
      </MenuItem>
    </AccountMenu>
  );
}

type FrameProps = { me: Me | undefined; children: React.ReactNode } & (
  | { area: 'admin'; current: AdminPlace }
  | { area: 'account'; current: AccountPlace }
);

export function Frame(props: FrameProps) {
  const { me, children } = props;
  return (
    <MeProvider value={me}>
      <AppShell
        storageKey="d3auth.sidebar"
        brand={<AppShellBrand href={props.area === 'admin' ? '/admin' : '/account'} name="D3 Auth" mark={icon(ShieldHalf, 20)} />}
        nav={
          props.area === 'admin' ? (
            me ? <AdminNav current={props.current} me={me} /> : null
          ) : (
            <AccountNav current={props.current} />
          )
        }
        footer={me ? <Account me={me} area={props.area} /> : null}
      >
        {children}
      </AppShell>
    </MeProvider>
  );
}
