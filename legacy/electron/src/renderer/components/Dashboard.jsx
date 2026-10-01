import React, { useState, useEffect, useCallback, useRef } from 'react';
const { ipcRenderer } = window.require('electron');

function formatSize(bytes) {
  if (!bytes) return '0 B';
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + sizes[i];
}

function Toast({ message, type, onClose }) {
  useEffect(() => {
    const t = setTimeout(onClose, 3000);
    return () => clearTimeout(t);
  }, []);
  return (
    <div className={`toast toast-${type}`}>
      <span>{type === 'success' ? '\u2713' : type === 'error' ? '\u2717' : '\u2139'}</span>
      <span>{message}</span>
    </div>
  );
}

function Dashboard({ onLock }) {
  const [view, setView] = useState('all');
  const [files, setFiles] = useState([]);
  const [notes, setNotes] = useState([]);
  const [passwords, setPasswords] = useState([]);
  const [folders, setFolders] = useState([]);
  const [currentFolder, setCurrentFolder] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedNote, setSelectedNote] = useState(null);
  const [selectedPassword, setSelectedPassword] = useState(null);
  const [showNoteModal, setShowNoteModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showFolderModal, setShowFolderModal] = useState(false);
  const [folderName, setFolderName] = useState('');
  const [stats, setStats] = useState({});
  const [search, setSearch] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [toasts, setToasts] = useState([]);
  const [viewMode, setViewMode] = useState('grid');
  const [sortBy, setSortBy] = useState('date');
  const [thumbCache, setThumbCache] = useState({});
  const [passwordCategory, setPasswordCategory] = useState(null);
  const dropRef = useRef(null);

  const addToast = (message, type = 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  const loadData = async () => {
    const f = await ipcRenderer.invoke('files:list', currentFolder, null, search || null);
    const n = await ipcRenderer.invoke('notes:list', currentFolder, search || null);
    const pw = await ipcRenderer.invoke('passwords:list', passwordCategory, search || null);
    const fo = await ipcRenderer.invoke('folders:list', currentFolder);
    const s = await ipcRenderer.invoke('stats:get');
    setFiles(f);
    setNotes(n);
    setPasswords(pw);
    setFolders(fo);
    setStats(s);
  };

  useEffect(() => { loadData(); }, [currentFolder, search, view, passwordCategory]);

  useEffect(() => {
    const loadThumbs = async () => {
      const newCache = {};
      for (const f of files) {
        if (f.thumbnail && !thumbCache[f.thumbnail]) {
          const b64 = await ipcRenderer.invoke('files:getThumbBase64', f.thumbnail);
          if (b64) newCache[f.thumbnail] = `data:image/jpeg;base64,${b64}`;
        }
      }
      if (Object.keys(newCache).length > 0) {
        setThumbCache(prev => ({ ...prev, ...newCache }));
      }
    };
    if (files.length > 0) loadThumbs();
  }, [files]);

  const processFiles = async (paths) => {
    if (!paths || paths.length === 0) return;
    setUploading(true);
    try {
      const result = await ipcRenderer.invoke('files:add', paths, currentFolder);
      if (result && result.error) {
        addToast(result.error, 'error');
      } else {
        addToast(`${paths.length} file${paths.length > 1 ? 's' : ''} encrypted and added`, 'success');
        loadData();
      }
    } catch (err) {
      addToast('Error: ' + (err.message || 'Unknown error'), 'error');
    }
    setUploading(false);
  };

  const handleAddFiles = async () => {
    try {
      const paths = await ipcRenderer.invoke('dialog:openFiles');
      await processFiles(paths);
    } catch (err) {
      addToast('Error opening file dialog: ' + err.message, 'error');
    }
  };

  const handleDrop = useCallback(async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
    const paths = Array.from(e.dataTransfer.files).map(f => f.path).filter(p => p);
    await processFiles(paths);
  }, [currentFolder]);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOver(false);
  }, []);

  useEffect(() => {
    const el = dropRef.current;
    if (el) {
      el.addEventListener('dragover', handleDragOver);
      el.addEventListener('dragleave', handleDragLeave);
      el.addEventListener('drop', handleDrop);
      return () => {
        el.removeEventListener('dragover', handleDragOver);
        el.removeEventListener('dragleave', handleDragLeave);
        el.removeEventListener('drop', handleDrop);
      };
    }
  }, [handleDrop, handleDragOver, handleDragLeave]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.ctrlKey && e.key === 'n') { e.preventDefault(); handleAddFiles(); }
      if (e.key === 'Escape') { setSelectedFile(null); setShowNoteModal(false); setShowFolderModal(false); setSelectedNote(null); setShowPasswordModal(false); setSelectedPassword(null); }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [currentFolder]);

  const handleAddFolder = async () => {
    if (folderName.trim()) {
      await ipcRenderer.invoke('folders:add', folderName.trim(), currentFolder);
      setFolderName('');
      setShowFolderModal(false);
      addToast('Folder created', 'success');
      loadData();
    }
  };

  const handleDeleteFile = async (id) => {
    await ipcRenderer.invoke('files:delete', id);
    setSelectedFile(null);
    addToast('File deleted', 'success');
    loadData();
  };

  const handleDeleteNote = async (id) => {
    await ipcRenderer.invoke('notes:delete', id);
    setSelectedNote(null);
    setShowNoteModal(false);
    addToast('Note deleted', 'success');
    loadData();
  };

  const handleDeletePassword = async (id) => {
    await ipcRenderer.invoke('passwords:delete', id);
    setSelectedPassword(null);
    setShowPasswordModal(false);
    addToast('Password deleted', 'success');
    loadData();
  };

  const handleDeleteFolder = async (id) => {
    await ipcRenderer.invoke('folders:delete', id);
    addToast('Folder deleted', 'success');
    loadData();
  };

  const handleLock = async () => {
    await ipcRenderer.invoke('app:lock');
    onLock();
  };

  const filteredFiles = files.filter(f => {
    if (view === 'photos') return f.file_type === 'photo';
    if (view === 'videos') return f.file_type === 'video';
    if (view === 'texts') return f.file_type === 'text';
    return true;
  });

  const sortedFiles = [...filteredFiles].sort((a, b) => {
    if (sortBy === 'date') return new Date(b.created_at) - new Date(a.created_at);
    if (sortBy === 'name') return a.original_name.localeCompare(b.original_name);
    if (sortBy === 'size') return (b.size || 0) - (a.size || 0);
    return 0;
  });

  const currentViewTitle = { all: 'All Files', photos: 'Photos', videos: 'Videos', texts: 'Text Files', notes: 'Notes', passwords: 'Passwords' };

  return (
    <div className="app-layout">
      <Sidebar
        view={view}
        setView={setView}
        folders={folders}
        currentFolder={currentFolder}
        setCurrentFolder={setCurrentFolder}
        stats={stats}
        search={search}
        setSearch={setSearch}
        onLock={handleLock}
        onAddFolder={() => setShowFolderModal(true)}
        onDeleteFolder={handleDeleteFolder}
      />
      <div className="main-content" ref={dropRef} style={{ position: 'relative' }}>
        {dragOver && (
          <div className="drop-overlay">
            <div className="drop-zone">
              <div className="drop-icon">&#128229;</div>
              <div className="drop-text">Drop files here to encrypt and store</div>
              <div className="drop-subtext">Photos, videos, text files - all encrypted with AES-256</div>
            </div>
          </div>
        )}
        {uploading && (
          <div className="upload-overlay">
            <div className="spinner" />
            <div style={{ marginTop: 16, fontSize: 14, color: 'var(--text-secondary)' }}>Encrypting files...</div>
          </div>
        )}
        <div className="toolbar">
          <div className="toolbar-left">
            <h2 className="toolbar-title">{currentViewTitle[view]}</h2>
            {(search || currentFolder) && (
              <button className="btn-clear" onClick={() => { setSearch(''); setCurrentFolder(null); }}>
                Clear filters &times;
              </button>
            )}
          </div>
          <div className="toolbar-right">
            <div className="toolbar-sort">
              <select value={sortBy} onChange={e => setSortBy(e.target.value)} className="sort-select">
                <option value="date">Recent</option>
                <option value="name">Name</option>
                <option value="size">Size</option>
              </select>
            </div>
            <div className="toolbar-view-toggle">
              <button className={`view-btn ${viewMode === 'grid' ? 'active' : ''}`} onClick={() => setViewMode('grid')} title="Grid view">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>
              </button>
              <button className={`view-btn ${viewMode === 'list' ? 'active' : ''}`} onClick={() => setViewMode('list')} title="List view">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><rect x="1" y="2" width="14" height="3" rx="1"/><rect x="1" y="7" width="14" height="3" rx="1"/><rect x="1" y="12" width="14" height="3" rx="1"/></svg>
              </button>
            </div>
            {view !== 'notes' && (
              <button className="btn btn-primary" onClick={handleAddFiles}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M7 0v14M0 7h14" strokeWidth="2"/></svg>
                Add Files
              </button>
            )}
            {view === 'notes' && (
              <button className="btn btn-primary" onClick={() => { setSelectedNote(null); setShowNoteModal(true); }}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M7 0v14M0 7h14" strokeWidth="2"/></svg>
                New Note
              </button>
            )}
            {view === 'passwords' && (
              <button className="btn btn-primary" onClick={() => { setSelectedPassword(null); setShowPasswordModal(true); }}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M7 0v14M0 7h14" strokeWidth="2"/></svg>
                New Password
              </button>
            )}
          </div>
        </div>
        <div className="content-area">
          {folders.length > 0 && (
            <div className="folders-section">
              <div className="section-header">
                <span className="section-label">Folders</span>
                <span className="section-count">{folders.length}</span>
              </div>
              <div className="folders-grid">
                {folders.map(f => (
                  <div key={f.id} className="folder-card" onClick={() => setCurrentFolder(f.id)}>
                    <div className="folder-card-icon">&#128193;</div>
                    <div className="folder-card-name">{f.name}</div>
                    <button className="folder-card-delete" onClick={(e) => { e.stopPropagation(); handleDeleteFolder(f.id); }} title="Delete folder">
                      <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><path d="M1 1l10 10M11 1L1 11" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {view === 'notes' ? (
            notes.length > 0 ? (
              <div className="notes-grid">
                {notes.map(n => (
                  <div key={n.id} className="note-card fade-in" onClick={() => { setSelectedNote(n); setShowNoteModal(true); }}>
                    <div className="note-card-header">
                      <div className="note-card-dot" />
                      <span className="note-card-date">{new Date(n.updated_at).toLocaleDateString()}</span>
                    </div>
                    <div className="note-card-title">{n.title}</div>
                    <div className="note-card-preview">{n.content?.substring(0, 150) || 'Empty note...'}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-state-visual">
                  <div className="empty-state-circle">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6"/><path d="M9 15h6"/></svg>
                  </div>
                </div>
                <h3 className="empty-state-title">No notes yet</h3>
                <p className="empty-state-text">Create your first encrypted note. All content is encrypted with AES-256.</p>
                <button className="btn btn-primary" onClick={() => { setSelectedNote(null); setShowNoteModal(true); }}>
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M7 0v14M0 7h14" strokeWidth="2"/></svg>
                  Create Note
                </button>
              </div>
            )
          ) : view === 'passwords' ? (
            passwords.length > 0 ? (
              <div className="passwords-list">
                <div className="password-categories">
                  {['all','social','email','banking','shopping','work','other'].map(cat => (
                    <button key={cat} className={`pw-cat-btn ${passwordCategory === (cat === 'all' ? null : cat) ? 'active' : ''}`} onClick={() => setPasswordCategory(cat === 'all' ? null : cat)}>
                      {cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
                    </button>
                  ))}
                </div>
                <div className="password-items">
                  {passwords.map(pw => (
                    <div key={pw.id} className="password-item fade-in" onClick={() => { setSelectedPassword(pw); setShowPasswordModal(true); }}>
                      <div className="pw-item-left">
                        <div className="pw-item-icon" style={{ background: pw.favorite ? 'var(--accent)' : 'var(--bg-tertiary)' }}>
                          {pw.name ? pw.name.charAt(0).toUpperCase() : '?'}
                        </div>
                        <div className="pw-item-info">
                          <div className="pw-item-name">{pw.name}</div>
                          <div className="pw-item-user">{pw.username || 'No username'}</div>
                        </div>
                      </div>
                      <div className="pw-item-right">
                        <span className="pw-item-category">{pw.category}</span>
                        <span className="pw-item-date">{new Date(pw.updated_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="empty-state">
                <div className="empty-state-visual">
                  <div className="empty-state-circle">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.5">
                      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/>
                    </svg>
                  </div>
                </div>
                <h3 className="empty-state-title">No passwords saved</h3>
                <p className="empty-state-text">Store your passwords encrypted with AES-256. All data stays on your device.</p>
                <button className="btn btn-primary" onClick={() => { setSelectedPassword(null); setShowPasswordModal(true); }}>
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M7 0v14M0 7h14" strokeWidth="2"/></svg>
                  Add Password
                </button>
              </div>
            )
          ) : (
            sortedFiles.length > 0 ? (
              viewMode === 'grid' ? (
                <div className="files-grid">
                  {sortedFiles.map(f => (
                    <div key={f.id} className="file-card fade-in" onClick={() => setSelectedFile(f)}>
                      <div className="file-card-thumb">
                        {f.thumbnail && thumbCache[f.thumbnail] ? (
                          <img className="thumb-blur" src={thumbCache[f.thumbnail]} alt={f.original_name} loading="lazy" />
                        ) : (
                          <div className={`file-card-icon file-type-${f.file_type}`}>
                            {f.file_type === 'video' ? (
                              <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
                            ) : f.file_type === 'text' ? (
                              <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg>
                            ) : (
                              <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
                            )}
                           </div>
                        )}
                      </div>
                      <div className="file-card-info">
                        <div className="file-card-name" title={f.original_name}>{f.original_name}</div>
                        <div className="file-card-meta">{formatSize(f.size)} &middot; {new Date(f.created_at).toLocaleDateString()}</div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="files-list">
                  <div className="list-header">
                    <span className="list-col-name">Name</span>
                    <span className="list-col-type">Type</span>
                    <span className="list-col-size">Size</span>
                    <span className="list-col-date">Date</span>
                  </div>
                  {sortedFiles.map(f => (
                    <div key={f.id} className="list-row" onClick={() => setSelectedFile(f)}>
                      <div className="list-col-name">
                        <div className={`file-type-dot file-type-${f.file_type}`} />
                        {f.original_name}
                      </div>
                      <span className="list-col-type">{f.file_type}</span>
                      <span className="list-col-size">{formatSize(f.size)}</span>
                      <span className="list-col-date">{new Date(f.created_at).toLocaleDateString()}</span>
                    </div>
                  ))}
                </div>
              )
            ) : (
              <div className="empty-state">
                <div className="empty-state-visual">
                  <div className="empty-state-circle">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="1.5">
                      {view === 'photos' ? <><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></> :
                       view === 'videos' ? <><polygon points="5 3 19 12 5 21 5 3"/></> :
                       <><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></>}
                    </svg>
                  </div>
                </div>
                <h3 className="empty-state-title">
                  {view === 'photos' ? 'No photos yet' : view === 'videos' ? 'No videos yet' : 'No files yet'}
                </h3>
                <p className="empty-state-text">
                  Drag and drop files here or click "Add Files". Supports JPG, PNG, GIF, MP4, AVI, TXT and more.
                </p>
                <button className="btn btn-primary" onClick={handleAddFiles}>
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M7 0v14M0 7h14" strokeWidth="2"/></svg>
                  Add Files
                </button>
              </div>
            )
          )}
        </div>
      </div>

      {selectedFile && <FileModal file={selectedFile} onClose={() => setSelectedFile(null)} onDelete={handleDeleteFile} />}
      {showNoteModal && (
        <NoteModal
          note={selectedNote}
          onSave={async (title, content) => {
            if (selectedNote) {
              await ipcRenderer.invoke('notes:update', selectedNote.id, title, content, selectedNote.tags || []);
              addToast('Note updated', 'success');
            } else {
              await ipcRenderer.invoke('notes:add', title, content, currentFolder);
              addToast('Note created', 'success');
            }
            setShowNoteModal(false);
            setSelectedNote(null);
            loadData();
          }}
          onDelete={selectedNote ? () => handleDeleteNote(selectedNote.id) : null}
          onClose={() => { setShowNoteModal(false); setSelectedNote(null); }}
        />
      )}
      {showFolderModal && (
        <div className="modal-overlay" onClick={() => setShowFolderModal(false)}>
          <div className="modal modal-sm fade-in" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title">New Folder</h3>
              <button className="modal-close" onClick={() => setShowFolderModal(false)}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M1 1l12 12M13 1L1 13" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
              </button>
            </div>
            <div className="input-group">
              <label>Folder Name</label>
              <input
                value={folderName}
                onChange={e => setFolderName(e.target.value)}
                placeholder="e.g., Vacation 2024"
                autoFocus
                onKeyDown={e => e.key === 'Enter' && handleAddFolder()}
              />
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={() => setShowFolderModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleAddFolder}>Create</button>
            </div>
          </div>
        </div>
      )}

      {showPasswordModal && (
        <PasswordModal
          password={selectedPassword}
          onSave={async (data) => {
            if (selectedPassword) {
              await ipcRenderer.invoke('passwords:update', selectedPassword.id, data.name, data.username, data.password, data.url, data.notes, data.category, data.favorite);
              addToast('Password updated', 'success');
            } else {
              await ipcRenderer.invoke('passwords:add', data.name, data.username, data.password, data.url, data.notes, data.category, data.favorite);
              addToast('Password saved', 'success');
            }
            setShowPasswordModal(false);
            setSelectedPassword(null);
            loadData();
          }}
          onDelete={selectedPassword ? () => handleDeletePassword(selectedPassword.id) : null}
          onToggleFavorite={selectedPassword ? async () => {
            await ipcRenderer.invoke('passwords:toggleFavorite', selectedPassword.id);
            loadData();
          } : null}
          onClose={() => { setShowPasswordModal(false); setSelectedPassword(null); }}
        />
      )}

      <div className="toast-container">
        {toasts.map(t => (
          <Toast key={t.id} message={t.message} type={t.type} onClose={() => removeToast(t.id)} />
        ))}
      </div>
    </div>
  );
}

function FileModal({ file, onClose, onDelete }) {
  const [tempPath, setTempPath] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [textContent, setTextContent] = React.useState('');

  React.useEffect(() => {
    let mounted = true;
    ipcRenderer.invoke('files:getPath', file.encrypted_name).then(p => {
      if (mounted) {
        setTempPath(p);
        if (file.file_type === 'text' && p) {
          try { setTextContent(window.require('fs').readFileSync(p, 'utf8')); } catch {}
        }
        setLoading(false);
      }
    });
    return () => { mounted = false; };
  }, []);

  const handleDecrypt = async () => { await ipcRenderer.invoke('files:decrypt', file.id); };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-xl fade-in" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="modal-title">{file.original_name}</h3>
          <div className="modal-actions">
            <button className="btn btn-secondary" onClick={handleDecrypt}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Export
            </button>
            <button className="btn btn-danger" onClick={() => onDelete(file.id)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              Delete
            </button>
            <button className="modal-close" onClick={onClose}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M1 1l12 12M13 1L1 13" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
            </button>
          </div>
        </div>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
            <div className="spinner" />
          </div>
        ) : (
          <div className="file-preview">
            {file.file_type === 'photo' && tempPath && (
              <div className="photo-viewer">
                <img src={`file://${tempPath}`} alt={file.original_name} />
              </div>
            )}
            {file.file_type === 'video' && tempPath && (
              <video className="video-player" controls autoPlay>
                <source src={`file://${tempPath}`} />
              </video>
            )}
            {file.file_type === 'text' && (
              <div className="text-viewer">
                <pre>{textContent}</pre>
              </div>
            )}
            <div className="file-info-bar">
              <span className="file-info-badge">{file.mime_type}</span>
              <span className="file-info-badge">{formatSize(file.size)}</span>
              <span className="file-info-badge">{new Date(file.created_at).toLocaleString()}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function NoteModal({ note, onSave, onDelete, onClose }) {
  const [title, setTitle] = useState(note?.title || '');
  const [content, setContent] = useState(note?.content || '');
  const textareaRef = useRef(null);

  useEffect(() => {
    if (textareaRef.current) textareaRef.current.focus();
  }, []);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-lg fade-in" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="modal-title">{note ? 'Edit Note' : 'New Note'}</h3>
          <div className="modal-actions">
            {onDelete && (
              <button className="btn btn-danger" onClick={onDelete}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Delete
              </button>
            )}
            <button className="modal-close" onClick={onClose}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M1 1l12 12M13 1L1 13" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
            </button>
          </div>
        </div>
        <div className="input-group">
          <label>Title</label>
          <input value={title} onChange={e => setTitle(e.target.value)} placeholder="Note title..." autoFocus />
        </div>
        <div className="input-group">
          <label>Content</label>
          <textarea
            ref={textareaRef}
            className="text-editor"
            value={content}
            onChange={e => setContent(e.target.value)}
            placeholder="Write your encrypted note here..."
          />
        </div>
        <div className="modal-actions" style={{ justifyContent: 'flex-end' }}>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={() => onSave(title, content)}>
            {note ? 'Update' : 'Save Note'}
          </button>
        </div>
      </div>
    </div>
  );
}

function PasswordModal({ password, onSave, onDelete, onToggleFavorite, onClose }) {
  const [name, setName] = useState(password?.name || '');
  const [username, setUsername] = useState(password?.username || '');
  const [pw, setPw] = useState(password?.password || '');
  const [url, setUrl] = useState(password?.url || '');
  const [notes, setNotes] = useState(password?.notes || '');
  const [category, setCategory] = useState(password?.category || 'other');
  const [favorite, setFavorite] = useState(password?.favorite === 1);
  const [showPw, setShowPw] = useState(false);
  const [copied, setCopied] = useState(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (inputRef.current) inputRef.current.focus();
  }, []);

  const copyToClipboard = async (text, field) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(field);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      setCopied(field);
      setTimeout(() => setCopied(null), 1500);
    }
  };

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
    let result = '';
    const arr = new Uint32Array(24);
    window.require('crypto').randomFillSync(arr);
    for (let i = 0; i < 24; i++) result += chars[arr[i] % chars.length];
    setPw(result);
  };

  const handleSave = () => {
    if (!name.trim()) return;
    onSave({ name: name.trim(), username: username.trim(), password: pw, url: url.trim(), notes, category, favorite });
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-md fade-in" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="modal-title">{password ? 'Edit Password' : 'New Password'}</h3>
          <div className="modal-actions">
            {password && (
              <button className="btn btn-secondary" onClick={onToggleFavorite} title={favorite ? 'Remove from favorites' : 'Add to favorites'}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill={favorite ? 'var(--warning)' : 'none'} stroke={favorite ? 'var(--warning)' : 'currentColor'} strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                {favorite ? 'Favorited' : 'Favorite'}
              </button>
            )}
            {onDelete && (
              <button className="btn btn-danger" onClick={onDelete}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Delete
              </button>
            )}
            <button className="modal-close" onClick={onClose}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M1 1l12 12M13 1L1 13" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
            </button>
          </div>
        </div>

        <div className="input-group">
          <label>Service Name *</label>
          <input ref={inputRef} value={name} onChange={e => setName(e.target.value)} placeholder="e.g., Google, Netflix, GitHub..." />
        </div>

        <div className="input-group">
          <label>Username / Email</label>
          <div className="pw-input-row">
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="user@email.com" />
            {username && (
              <button className="btn-copy" onClick={() => copyToClipboard(username, 'user')} title="Copy username">
                {copied === 'user' ? '\u2713' : '\u2398'}
              </button>
            )}
          </div>
        </div>

        <div className="input-group">
          <label>Password</label>
          <div className="pw-input-row">
            <input
              type={showPw ? 'text' : 'password'}
              value={pw}
              onChange={e => setPw(e.target.value)}
              placeholder="Enter or generate password"
              className="pw-field"
            />
            <button className="btn-copy" onClick={() => setShowPw(!showPw)} title={showPw ? 'Hide' : 'Show'}>
              {showPw ? '\u{1F441}' : '\u{1F441}\u200D\u{1F5E8}'}
            </button>
            <button className="btn-copy" onClick={() => copyToClipboard(pw, 'pw')} title="Copy password">
              {copied === 'pw' ? '\u2713' : '\u2398'}
            </button>
            <button className="btn-generate" onClick={generatePassword} title="Generate strong password">
              &#x21BB;
            </button>
          </div>
        </div>

        <div className="input-group">
          <label>URL</label>
          <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" />
        </div>

        <div className="input-group">
          <label>Category</label>
          <div className="pw-categories-row">
            {['social','email','banking','shopping','work','other'].map(cat => (
              <button key={cat} className={`pw-cat-chip ${category === cat ? 'active' : ''}`} onClick={() => setCategory(cat)}>
                {cat.charAt(0).toUpperCase() + cat.slice(1)}
              </button>
            ))}
          </div>
        </div>

        <div className="input-group">
          <label>Notes</label>
          <textarea className="text-editor" value={notes} onChange={e => setNotes(e.target.value)} placeholder="Additional notes..." style={{ minHeight: 100 }} />
        </div>

        <div className="modal-actions" style={{ justifyContent: 'flex-end' }}>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={handleSave} disabled={!name.trim()}>
            {password ? 'Update' : 'Save Password'}
          </button>
        </div>
      </div>
    </div>
  );
}

function Sidebar({ view, setView, folders, currentFolder, setCurrentFolder, stats, search, setSearch, onLock, onAddFolder, onDeleteFolder }) {
  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="white"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <span className="sidebar-logo-text">Vault</span>
          <span className="sidebar-version">v1.0</span>
        </div>
        <div className="search-box">
          <svg className="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input
            type="text"
            placeholder="Search files, notes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="sidebar-nav">
        <div className="sidebar-section">
          <div className="sidebar-section-title">Library</div>
          <NavButton icon={<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>} label="All Files" count={(stats.photos || 0) + (stats.videos || 0) + (stats.texts || 0)} active={view === 'all'} onClick={() => { setView('all'); setCurrentFolder(null); }} />
          <NavButton icon={<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>} label="Photos" count={stats.photos || 0} active={view === 'photos'} onClick={() => { setView('photos'); setCurrentFolder(null); }} />
          <NavButton icon={<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>} label="Videos" count={stats.videos || 0} active={view === 'videos'} onClick={() => { setView('videos'); setCurrentFolder(null); }} />
          <NavButton icon={<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 18v-6"/><path d="M9 15h6"/></svg>} label="Text Files" count={stats.texts || 0} active={view === 'texts'} onClick={() => { setView('texts'); setCurrentFolder(null); }} />
          <NavButton icon={<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>} label="Notes" count={stats.notes || 0} active={view === 'notes'} onClick={() => { setView('notes'); setCurrentFolder(null); }} />
          <NavButton icon={<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>} label="Passwords" count={stats.passwords || 0} active={view === 'passwords'} onClick={() => { setView('passwords'); setCurrentFolder(null); }} />
        </div>

        <div className="sidebar-section">
          <div className="sidebar-section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            Folders
            <button className="btn-add-folder" onClick={onAddFolder} title="New folder">
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor"><path d="M6 0v12M0 6h12" stroke="currentColor" strokeWidth="1.5" fill="none"/></svg>
            </button>
          </div>
          <div className="folders-list">
            {folders.map(f => (
              <button
                key={f.id}
                className={`folder-nav-item ${currentFolder === f.id ? 'active' : ''}`}
                onClick={() => setCurrentFolder(f.id)}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                <span>{f.name}</span>
                <button
                  className="folder-nav-delete"
                  onClick={(e) => { e.stopPropagation(); onDeleteFolder(f.id); }}
                >
                  <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M1 1l8 8M9 1L1 9"/></svg>
                </button>
              </button>
            ))}
            {folders.length === 0 && (
              <div className="folders-empty">No folders yet</div>
            )}
          </div>
        </div>
      </div>

      <div className="sidebar-footer">
        <div className="storage-info">
          <div className="storage-bar">
            <div className="storage-bar-fill" style={{ width: `${Math.min(100, (stats.totalSize || 0) / 1024 / 1024 / 10)}%` }} />
          </div>
          <span className="storage-text">{stats.totalSize ? `${(stats.totalSize / 1024 / 1024).toFixed(1)} MB` : '0 B'} stored</span>
        </div>
        <button className="btn btn-lock" onClick={onLock}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Lock Vault
        </button>
      </div>
    </div>
  );
}

function NavButton({ icon, label, count, active, onClick }) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>
      <span className="nav-item-icon">{icon}</span>
      <span className="nav-item-label">{label}</span>
      <span className="nav-item-count">{count}</span>
    </button>
  );
}

export default Dashboard;
