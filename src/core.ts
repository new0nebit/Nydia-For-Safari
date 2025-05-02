import './algorithms';
import './authenticator';
import './logger';
import './store';
import './types';

import { initializeAuthenticator } from './authenticator';

// Initializes the WebAuthn authenticator when the core script is loaded.
initializeAuthenticator();
