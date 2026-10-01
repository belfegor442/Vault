import React, { useState, useEffect } from 'react';
const { ipcRenderer } = window.require('electron');

function Login({ onUnlock }) {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isNew, setIsNew] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [hasFingerprint, setHasFingerprint] = useState(false);
  const [fingerprintLoading, setFingerprintLoading] = useState(false);

  useEffect(() => {
    ipcRenderer.invoke('auth:isInitialized').then(init => {
      setIsNew(!init);
      if (init) {
        ipcRenderer.invoke('webauthn:hasCredential').then(setHasFingerprint);
      }
    });
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown(prev => prev - 1), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isNew) {
        if (password.length < 8) {
          setError('Password must be at least 8 characters');
          setLoading(false);
          return;
        }
        if (password !== confirmPassword) {
          setError('Passwords do not match');
          setLoading(false);
          return;
        }
        const result = await ipcRenderer.invoke('auth:setup', password);
        if (result.success) {
          const regResult = await ipcRenderer.invoke('webauthn:register');
          if (regResult.success) {
            setHasFingerprint(true);
          }
          onUnlock();
        }
      } else {
        const result = await ipcRenderer.invoke('auth:login', password);
        if (result.success) {
          onUnlock();
        } else {
          setError(result.error);
          if (result.lockedOut) setCooldown(300);
        }
      }
    } catch (err) {
      setError('An error occurred');
    }
    setLoading(false);
  };

  const handleFingerprint = async () => {
    setError('');
    setFingerprintLoading(true);
    try {
      const result = await ipcRenderer.invoke('webauthn:authenticate');
      if (result.success) {
        ipcRenderer.invoke('auth:isUnlocked').then(unlocked => {
          if (unlocked) {
            onUnlock();
          } else {
            setError('Fingerprint verified but vault is locked. Enter password first.');
          }
        });
      } else {
        setError(result.error || 'Fingerprint authentication failed');
      }
    } catch (err) {
      setError('Fingerprint error: ' + err.message);
    }
    setFingerprintLoading(false);
  };

  const handleRegisterFingerprint = async () => {
    setFingerprintLoading(true);
    setError('');
    try {
      const result = await ipcRenderer.invoke('webauthn:register');
      if (result.success) {
        setHasFingerprint(true);
      } else {
        setError(result.error || 'Failed to register fingerprint');
      }
    } catch (err) {
      setError('Registration error: ' + err.message);
    }
    setFingerprintLoading(false);
  };

  return (
    <div className="login-screen">
      <div className="login-box">
        <div className="login-icon">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="white">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </div>
        <h1 className="login-title">Vault</h1>
        <p className="login-subtitle">
          {isNew
            ? 'Create a master password to protect your vault'
            : 'Enter your master password to unlock'}
        </p>

        {!isNew && hasFingerprint && (
          <button
            className="btn btn-fingerprint"
            onClick={handleFingerprint}
            disabled={fingerprintLoading || cooldown > 0}
            style={{ width: '100%', justifyContent: 'center', padding: '14px 20px', marginBottom: 16 }}
          >
            <span className="fingerprint-icon">{fingerprintLoading ? '...' : '\u{1F5B1}'}</span>
            {fingerprintLoading ? 'Authenticating...' : 'Unlock with Fingerprint'}
          </button>
        )}

        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <label>Master Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={isNew ? 'Minimum 8 characters...' : 'Enter password...'}
              autoFocus
              disabled={cooldown > 0}
            />
          </div>
          {isNew && (
            <div className="input-group">
              <label>Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm password..."
              />
            </div>
          )}
          <button
            className="btn btn-primary"
            type="submit"
            disabled={loading || cooldown > 0}
            style={{ width: '100%', justifyContent: 'center', padding: '13px 20px' }}
          >
            {cooldown > 0
              ? `Locked - ${cooldown}s`
              : loading
                ? '...'
                : isNew
                  ? 'Create Vault'
                  : 'Unlock'}
          </button>
        </form>

        {isNew && !hasFingerprint && (
          <button
            className="btn btn-fingerprint"
            onClick={handleRegisterFingerprint}
            disabled={fingerprintLoading}
            style={{ width: '100%', justifyContent: 'center', padding: '14px 20px', marginTop: 12 }}
          >
            <span className="fingerprint-icon">{fingerprintLoading ? '...' : '\u{1F5B1}'}</span>
            {fingerprintLoading ? 'Setting up...' : 'Enable Fingerprint Unlock'}
          </button>
        )}

        {error && <p className="error-msg">{error}</p>}
        <div className="security-info">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          AES-256-GCM + HMAC integrity verification
        </div>
      </div>
    </div>
  );
}

export default Login;
