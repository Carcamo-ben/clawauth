# @clawauth/client

Browser SDK for clawauth. Three lines:

```ts
import { createClawAuthClient } from '@clawauth/client';
const auth = createClawAuthClient({ googleClientId: 'YOUR_ID.apps.googleusercontent.com' });
document.getElementById('signin').onclick = () => auth.signInWithGoogle();
```

After sign-in, use `auth.fetch(url)` to call your API — it adds the Bearer token and auto-refreshes on 401.
