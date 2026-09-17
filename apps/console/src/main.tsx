import '@d3cloud/ui/tokens.css';
import '@d3cloud/ui/base.css';
import './styles.css';
import { readStyleNonce, setStyleNonce } from '@d3cloud/ui';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App, loadSurface } from './App';
import { surfaceFor } from './surface';

const root = document.getElementById('root');
if (!root) throw new Error('Missing #root');

// The CSP allows runtime styles (the dialogs' scroll lock) only with this response's nonce, which
// the server puts in <meta name="d3-style-nonce">. It must be set before anything renders.
const styleNonce = readStyleNonce();
if (styleNonce) setStyleNonce(styleNonce);

const surface = surfaceFor(window.location.pathname);

// Some pages arrive complete from the server. Mounting React over them would throw away the very
// thing the person was sent to read.
if (surface !== 'server-rendered') {
  // The surface's chunk is fetched before React mounts, so the server-rendered sign-in form stays on
  // screen until the screen that replaces it is ready, rather than giving way to a blank page.
  void loadSurface(surface).then((Surface) => {
    createRoot(root).render(
      <StrictMode>
        <App Surface={Surface} />
      </StrictMode>,
    );
  });
}
