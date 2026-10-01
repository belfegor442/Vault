import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';

const { ipcRenderer } = window.require('electron');

function App() {
  const [unlocked, setUnlocked] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    ipcRenderer.invoke('auth:isUnlocked').then(setUnlocked).finally(() => setLoading(false));
  }, []);

  const handleUnlock = () => setUnlocked(true);
  const handleLock = () => setUnlocked(false);

  if (loading) {
    return (
      <div className="login-screen">
        <div className="spinner" />
      </div>
    );
  }

  return (
    <>
      <div className="titlebar">
        <span className="titlebar-title">VAULT</span>
        <div className="titlebar-buttons">
          <button className="titlebar-btn btn-minimize" onClick={() => ipcRenderer.invoke('window:minimize')} />
          <button className="titlebar-btn btn-maximize" onClick={() => ipcRenderer.invoke('window:maximize')} />
          <button className="titlebar-btn btn-close" onClick={() => ipcRenderer.invoke('window:close')} />
        </div>
      </div>
      {unlocked ? <Dashboard onLock={handleLock} /> : <Login onUnlock={handleUnlock} />}
    </>
  );
}

export default App;
