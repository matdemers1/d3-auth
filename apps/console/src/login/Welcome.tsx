import { LoginLayout } from './LoginLayout';

// Where the invite wizard lands.
export function Welcome() {
  return (
    <LoginLayout
      title="Your account is ready"
      description="Go back to the app you were invited to and sign in. Your username and password work everywhere that uses D3 Auth."
      footer={<>You can add a passkey from Security in your account at any time.</>}
    />
  );
}
