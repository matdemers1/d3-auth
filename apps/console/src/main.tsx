import '@d3cloud/ui/tokens.css';
import './styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { surfaceFor } from './surface';

const root = document.getElementById('root');
if (!root) throw new Error('Missing #root');

// Some pages arrive complete from the server. Mounting React over them would throw away the very
// thing the person was sent to read.
if (surfaceFor(window.location.pathname) !== 'server-rendered') {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
