const html = document.documentElement; //Dark and light theme 
    const toggle = document.querySelector('[data-theme-toggle]');
    let theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    function syncTheme(){html.setAttribute('data-theme', theme);toggle.innerHTML=theme==='dark'?'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>':'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';}
    toggle.addEventListener('click',()=>{theme=theme==='dark'?'light':'dark';syncTheme();}); syncTheme();

    const state = { //Demo credentials
      username: 'admin',
      passwordHash: null,
      salt: 'dual-auth-demo-salt-v1',
      googleSecret: '',
      microsoftSecret: ''
    };

    const el = id => document.getElementById(id); //Get elements by ID
    const statusEl = el('status'); 
    const successCard = el('successCard');

    function setStatus(type, text){ //Update status message and style
      statusEl.className = 'status ' + type;
      statusEl.textContent = text;
    }

    const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; //Base32 characters

    function randomBase32(length = 32) { //Generate random Base32 string
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      let out = '';
      for (let i = 0; i < length; i++) out += base32Alphabet[bytes[i] % 32];
      return out;
    }

    function base32ToBytes(base32) { //Convert Base32 string to bytes
      const cleaned = base32.toUpperCase().replace(/=+$/,'').replace(/[^A-Z2-7]/g,'');
      let bits = '';
      for (const char of cleaned) bits += base32Alphabet.indexOf(char).toString(2).padStart(5,'0');
      const bytes = [];
      for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
      return new Uint8Array(bytes);
    }

    function otpauthURI(label, issuer, secret) { //Generate otpauth URI for QR code
      return `otpauth://totp/${encodeURIComponent(issuer + ':' + label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    }

    function drawQr(containerId, text) { //Draw QR code in specified container
      const node = el(containerId);
      node.innerHTML = '';
      new QRCode(node, { text, width: 160, height: 160, correctLevel: QRCode.CorrectLevel.M });
    }

    async function hmacSha1(secretBytes, counter) { //Calculate HMAC-SHA1 for given secret and counter
      const key = await crypto.subtle.importKey('raw', secretBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
      const buf = new ArrayBuffer(8);
      const view = new DataView(buf);
      view.setUint32(4, counter);
      const sig = await crypto.subtle.sign('HMAC', key, buf);
      return new Uint8Array(sig);
    }

    async function generateTOTP(secret, timeStep = 30, digits = 6, forTime = Date.now()) { //Generate TOTP code for given secret and time
      const counter = Math.floor(forTime / 1000 / timeStep);
      const hmac = await hmacSha1(base32ToBytes(secret), counter);
      const offset = hmac[hmac.length - 1] & 0x0f;
      const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
      return String(binCode % (10 ** digits)).padStart(digits, '0');
    }

    async function verifyTOTP(secret, code) { //Verify TOTP code with a window of ±1 time step
      const clean = String(code || '').replace(/\D/g,'');
      if (clean.length !== 6) return false;
      const windows = [-1, 0, 1];
      for (const drift of windows) {
        const valid = await generateTOTP(secret, 30, 6, Date.now() + drift * 30000);
        if (valid === clean) return true;
      }
      return false;
    }

    async function hashPassword(password) { //Hash password using PBKDF2 with the demo salt
      const enc = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt: enc.encode(state.salt), iterations: 100000, hash:'SHA-256' }, keyMaterial, 256);
      return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2,'0')).join('');
    }

    async function initDemoCredentials() { //Initialize demo credentials by hashing the demo password
      state.passwordHash = await hashPassword('Password123!');
    }

    function generateSetup() { //Generate new secrets for both authenticators and update the UI
      state.googleSecret = randomBase32();
      state.microsoftSecret = randomBase32();
      el('googleSecret').textContent = state.googleSecret;
      el('microsoftSecret').textContent = state.microsoftSecret;
      drawQr('googleQr', otpauthURI(state.username, 'DualAuthDemo-Google', state.googleSecret));
      drawQr('microsoftQr', otpauthURI(state.username, 'DualAuthDemo-Microsoft', state.microsoftSecret));
      successCard.style.display = 'none';
      setStatus('ok', 'Setup ready. Scan one or both QR codes, then enter a current 6-digit code from either app.');
    }

    el('generateBtn').addEventListener('click', generateSetup);
    el('fillDemoBtn').addEventListener('click', () => { //Fill in demo credentials for quick testing
      el('username').value = 'admin';
      el('password').value = 'Password123!';
      setStatus('warn', 'Demo credentials filled. You still need to scan at least one QR code and enter one valid TOTP code.');
    });

    el('copySecretsBtn').addEventListener('click', async () => { //Copy secrets to clipboard for manual entry into authenticator apps
      if (!state.googleSecret || !state.microsoftSecret) return setStatus('warn', 'Generate the setup first.');
      const text = `Google secret: ${state.googleSecret}\nMicrosoft secret: ${state.microsoftSecret}`;
      await navigator.clipboard.writeText(text);
      setStatus('ok', 'Secrets copied to clipboard.');
    });

    document.getElementById('loginForm').addEventListener('submit', async (e) => { //Handle login form submission and perform authentication checks
      e.preventDefault();
      successCard.style.display = 'none';
      if (!state.googleSecret || !state.microsoftSecret) return setStatus('warn', 'Generate setup first so the authenticator secrets exist.');
      const username = el('username').value.trim();
      const password = el('password').value;
      if (username !== state.username) return setStatus('err', 'Username is incorrect. Use admin for this demo.');
      const incomingHash = await hashPassword(password);
      if (incomingHash !== state.passwordHash) return setStatus('err', 'Password is incorrect. Use Password123! for this demo.');
      const googleInput = el('googleCode').value.trim();
      const microsoftInput = el('microsoftCode').value.trim();
      if (!googleInput && !microsoftInput) return setStatus('warn', 'Enter either a Google Authenticator code or a Microsoft Authenticator code.');
      let method = '';
      if (googleInput) {
        const googleOK = await verifyTOTP(state.googleSecret, googleInput);
        if (!googleOK) return setStatus('err', 'Google Authenticator code is invalid or expired.');
        method = 'Google Authenticator';
      } else if (microsoftInput) {
        const microsoftOK = await verifyTOTP(state.microsoftSecret, microsoftInput);
        if (!microsoftOK) return setStatus('err', 'Microsoft Authenticator code is invalid or expired.');
        method = 'Microsoft Authenticator';
      }
      setStatus('ok', `Authenticated with ${method}. Username, password, and one authenticator code passed.`); //All checks passed, show success message
      successCard.style.display = 'block';
    });

    initDemoCredentials(); //Initialize the demo credentials when the page loads
