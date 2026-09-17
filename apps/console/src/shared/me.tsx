import { createContext, useContext, useEffect, useState } from 'react';
import { api, type Me } from '../api';

// Who is signed in, asked once by the frame and read by any page that needs it: the account menu
// names them, the nav leaves out what their role can never use, and a denied page names the
// operator who can say yes.

const MeContext = createContext<Me | undefined>(undefined);

export const MeProvider = MeContext.Provider;

/** Undefined until `/api/me` has answered. */
export const useMe = (): Me | undefined => useContext(MeContext);

/** "Ask Matthew", or a person-shaped fallback while nobody has said who runs this instance. */
export const useOperator = (): string => useMe()?.operatorDisplayName ?? 'the person who runs D3 Auth';

export function useLoadMe(): Me | undefined {
  const [me, setMe] = useState<Me | undefined>();
  useEffect(() => {
    api
      .get<Me>('/api/me')
      .then(setMe)
      .catch(() => {
        // A missing session redirects inside `api`. Anything else leaves the menu out; the page
        // itself still loads and reports its own failure where it happens.
      });
  }, []);
  return me;
}

export const KIND_LABEL: Record<Me['kind'], string> = { owner: 'Owner', admin: 'Admin', guest: 'Guest' };
