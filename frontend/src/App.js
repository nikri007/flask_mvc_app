import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

axios.defaults.baseURL = 'http://localhost:5000/api';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [view, setView] = useState('login');
  const [shareToken, setShareToken] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const urlToken = params.get('token');
    const resetToken = params.get('reset');
    
    if (urlToken) { setShareToken(urlToken); setView('publicShare'); }
    else if (resetToken) { setShareToken(resetToken); setView('resetPassword'); }
  }, []);

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setView('login');
  };

  if (shareToken && view === 'publicShare') return <PublicShare token={shareToken} />;
  if (shareToken && view === 'resetPassword') return <ResetPassword token={shareToken} />;
  if (!token) return <AuthScreen setToken={setToken} view={view} setView={setView} />;
  return <Dashboard token={token} logout={logout} />;
}

// Compact Auth Screen (Login, Register, Forgot Password)
function AuthScreen({ setToken, view, setView }) {
  const [data, setData] = useState({});
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    try {
      const endpoints = { login: '/auth/login', register: '/auth/register', forgot: '/auth/forgot-password' };
      const res = await axios.post(endpoints[view], data);
      
      if (res.data.token) {
        localStorage.setItem('token', res.data.token);
        setToken(res.data.token);
      } else {
        setMsg('Success! Check email for reset link.');
        setTimeout(() => setView('login'), 2000);
      }
    } catch (err) {
      setMsg(err.response?.data?.error || 'Error occurred');
    }
  };

  const change = (e) => setData({ ...data, [e.target.name]: e.target.value });

  // Convert date from dd/mm/yyyy to yyyy-mm-dd for backend
  const handleDateChange = (e) => {
    const dateValue = e.target.value;
    if (dateValue) {
      // Date input gives yyyy-mm-dd, backend expects yyyy-mm-dd, so no conversion needed
      setData({ ...data, date_of_birth: dateValue });
    }
  };

  return (
    <div className="auth-container">
      <h2>{view === 'register' ? 'Create Account' : view === 'forgot' ? 'Reset Password' : 'Sign In'}</h2>
      <form onSubmit={submit} className="auth-form">
        {view === 'register' && (
          <>
            <div className="form-group">
              <label>First Name</label>
              <input name="first_name" type="text" onChange={change} required />
            </div>
            <div className="form-group">
              <label>Last Name</label>
              <input name="last_name" type="text" onChange={change} required />
            </div>
            <div className="form-group">
              <label>Date of Birth</label>
              <input 
                name="date_of_birth" 
                type="date" 
                onChange={handleDateChange} 
                required 
                placeholder="dd/mm/yyyy"
                title="Please enter your date of birth in DD/MM/YYYY format"
              />
              <small className="date-hint">📅 Select your birth date (DD/MM/YYYY format)</small>
            </div>
            <div className="form-group">
              <label>Email Address</label>
              <input name="email" type="email" onChange={change} required />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input name="password" type="password" onChange={change} required />
            </div>
            <div className="form-group">
              <label>Confirm Password</label>
              <input name="confirm_password" type="password" onChange={change} required />
            </div>
          </>
        )}
        
        {view === 'login' && (
          <>
            <div className="form-group">
              <label>Email Address</label>
              <input name="email" type="email" onChange={change} required />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input name="password" type="password" onChange={change} required />
            </div>
          </>
        )}

        {view === 'forgot' && (
          <div className="form-group">
            <label>Email Address</label>
            <input name="email" type="email" placeholder="Enter your registered email" onChange={change} required />
          </div>
        )}
        
        <button type="submit" className="submit-btn">
          {view === 'register' ? 'Create Account' : view === 'forgot' ? 'Send Reset Link' : 'Sign In'}
        </button>
      </form>
      
      {msg && <div className={`message ${msg.includes('Error') ? 'error' : 'success'}`}>{msg}</div>}
      
      <div className="auth-links">
        {view === 'login' && (
          <>
            <button onClick={() => setView('register')} className="link-btn">
              Don't have an account? <strong>Create Account</strong>
            </button>
            <button onClick={() => setView('forgot')} className="link-btn">
              Forgot your password? <strong>Reset Password</strong>
            </button>
          </>
        )}
        {view === 'register' && (
          <button onClick={() => setView('login')} className="link-btn">
            Already have an account? <strong>Sign In</strong>
          </button>
        )}
        {view === 'forgot' && (
          <button onClick={() => setView('login')} className="link-btn">
            Remember your password? <strong>Back to Sign In</strong>
          </button>
        )}
      </div>
    </div>
  );
}

// Reset Password Component
function ResetPassword({ token }) {
  const [data, setData] = useState({ token, new_password: '', confirm_password: '' });
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    if (data.new_password !== data.confirm_password) {
      setMsg('Passwords do not match!');
      return;
    }
    try {
      await axios.post('/auth/reset-password', data);
      setMsg('Password reset successful! Redirecting to login...');
      setTimeout(() => window.location.href = '/', 2000);
    } catch (err) {
      setMsg(err.response?.data?.error || 'Reset failed');
    }
  };

  const change = (e) => setData({...data, [e.target.name]: e.target.value});

  return (
    <div className="auth-container">
      <h2>Reset Your Password</h2>
      <form onSubmit={submit} className="auth-form">
        <div className="form-group">
          <label>New Password</label>
          <input name="new_password" type="password" onChange={change} required />
        </div>
        <div className="form-group">
          <label>Confirm New Password</label>
          <input name="confirm_password" type="password" onChange={change} required />
        </div>
        <button type="submit" className="submit-btn">Reset Password</button>
      </form>
      {msg && <div className={`message ${msg.includes('successful') ? 'success' : 'error'}`}>{msg}</div>}
      
      <div className="password-requirements">
        <p><strong>Password Requirements:</strong></p>
        <ul>
          <li>At least 8 characters long</li>
          <li>One uppercase letter (A-Z)</li>
          <li>One lowercase letter (a-z)</li>
          <li>One number (0-9)</li>
          <li>One special character (!@#$%^&*)</li>
        </ul>
      </div>
    </div>
  );
}

// Main Dashboard
function Dashboard({ token, logout }) {
  const [view, setView] = useState('files');
  const [files, setFiles] = useState([]);
  const [shares, setShares] = useState([]);
  const [search, setSearch] = useState('');
  const [msg, setMsg] = useState('');

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    if (view === 'files') loadFiles();
    if (view === 'shares') loadShares();
  }, [view, search]);

  const loadFiles = async () => {
    try {
      const res = await axios.get(`/files?search=${search}`, { headers });
      setFiles(res.data.files);
    } catch { setMsg('Error loading files'); }
  };

  const loadShares = async () => {
    try {
      const res = await axios.get('/share/my-shares', { headers });
      setShares(res.data.shares);
    } catch { setMsg('Error loading shares'); }
  };

  const upload = async (e) => {
    const formData = new FormData();
    [...e.target.files].forEach(file => formData.append('files', file));
    try {
      await axios.post('/files/upload', formData, { headers: {...headers, 'Content-Type': 'multipart/form-data'} });
      setMsg('Upload successful!'); loadFiles();
    } catch { setMsg('Upload failed'); }
  };

  const deleteFile = async (id) => {
    if (!confirm('Delete file?')) return;
    try {
      await axios.delete(`/files/${id}`, { headers });
      setMsg('File deleted'); loadFiles();
    } catch { setMsg('Delete failed'); }
  };

  const download = async (id, name) => {
    try {
      const res = await axios.get(`/files/${id}/download`, { headers, responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url; a.download = name; a.click();
    } catch { setMsg('Download failed'); }
  };

  return (
    <div className="dashboard">
      <div className="header">
        <h1>File Share</h1>
        <div className="nav-buttons">
          {['files', 'shares', 'share', 'password'].map(v => (
            <button key={v} onClick={() => setView(v)} className={view === v ? 'active' : ''}>
              {v === 'files' ? 'Files' : v === 'shares' ? 'Shares' : v === 'share' ? 'Share' : 'Password'}
            </button>
          ))}
          <button onClick={logout} className="logout-btn">Logout</button>
        </div>
      </div>

      {msg && <div className="message">{msg}</div>}

      {view === 'files' && <FilesView files={files} search={search} setSearch={setSearch} upload={upload} deleteFile={deleteFile} download={download} />}
      {view === 'shares' && <SharesView shares={shares} />}
      {view === 'share' && <ShareView token={token} setMsg={setMsg} files={files} />}
      {view === 'password' && <PasswordView token={token} setMsg={setMsg} />}
    </div>
  );
}

// Files View with Properly Contained Drag & Drop
function FilesView({ files, search, setSearch, upload, deleteFile, download }) {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      upload({ target: { files: e.dataTransfer.files } });
    }
  };

  const handleFileSelect = (e) => {
    e.stopPropagation(); // Prevent event bubbling
    upload(e);
  };

  const handleDragAreaClick = (e) => {
    // Only trigger file input if clicking directly on drag area, not on buttons
    if (e.target.classList.contains('drag-drop-area') || 
        e.target.classList.contains('drag-drop-content') ||
        e.target.classList.contains('drag-icon') ||
        e.target.classList.contains('drag-title') ||
        e.target.classList.contains('drag-subtitle')) {
      document.getElementById('file-upload').click();
    }
  };

  return (
    <div className="view-container">
      {/* Properly Isolated Drag & Drop Area */}
      <div 
        className={`drag-drop-area ${dragActive ? 'drag-active' : ''}`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={handleDragAreaClick}
      >
        <div className="drag-drop-content">
          <div className="drag-icon">📂</div>
          <h3 className="drag-title">Drag & Drop Files Here</h3>
          <p className="drag-subtitle">or click to browse files</p>
          <div className="drag-details">
            <span>📁 Multiple files supported</span>
            <span>📏 Max 100MB per file</span>
            <span>🔒 Secure upload</span>
          </div>
          {/* File input - NO absolute positioning */}
          <input 
            type="file" 
            multiple 
            onChange={handleFileSelect} 
            id="file-upload" 
            style={{ display: 'none' }}
          />
          <button 
            type="button"
            className="browse-btn"
            onClick={(e) => {
              e.stopPropagation();
              document.getElementById('file-upload').click();
            }}
          >
            Choose Files
          </button>
        </div>
        {dragActive && (
          <div className="drag-overlay">
            <div className="drag-overlay-content">
              <div className="drag-overlay-icon">📥</div>
              <div className="drag-overlay-text">Drop files to upload</div>
            </div>
          </div>
        )}
      </div>

      {/* Search Bar */}
      <div className="search-section">
        <input 
          type="text" 
          placeholder="🔍 Search your files..." 
          value={search} 
          onChange={(e) => setSearch(e.target.value)}
          className="search-input"
        />
      </div>
      
      {/* Files List */}
      <div className="files-header">
        <h3>Your Files ({files.length})</h3>
      </div>
      
      <div className="list">
        {files.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📁</div>
            <h4>No files yet</h4>
            <p>Upload your first file using the drag & drop area above</p>
          </div>
        ) : (
          files.map(f => (
            <div key={f.id} className="item">
              <div className="info">
                <span className="name">📄 {f.filename}</span>
                <span className="size">{(f.size/1024/1024).toFixed(2)}MB</span>
                <span className="date">{new Date(f.created_at).toLocaleDateString()}</span>
              </div>
              <div className="actions">
                <button onClick={() => download(f.id, f.filename)} className="btn-green">
                 ⬇️ Download
                </button>
                <button onClick={() => deleteFile(f.id)} className="btn-red">
                  🗑️ Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Shares View
function SharesView({ shares }) {
  return (
    <div className="view-container">
      <h3>My Shared Files</h3>
      <div className="list">
        {shares.length === 0 ? (
          <div className="empty">No shared files</div>
        ) : (
          shares.map(s => (
            <div key={s.id} className="item">
              <div className="info">
                <span className="name">{s.file_name}</span>
                <span className="email">{s.recipient_email}</span>
                <span className="date">{new Date(s.created_at).toLocaleDateString()}</span>
              </div>
              <div className="status">
                <span className={s.accessed ? 'accessed' : 'pending'}>
                  {s.accessed ? '✅ Accessed' : '⏳ Pending'}
                </span>
                <span className="count">Views: {s.access_count}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Share File View
function ShareView({ token, setMsg, files }) {
  const [data, setData] = useState({ file_id: '', recipient_email: '', expiration_hours: '24', message: '' });

  const submit = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/share/create', data, { headers: { Authorization: `Bearer ${token}` } });
      setMsg('File shared successfully! Email sent to recipient.');
      setData({ file_id: '', recipient_email: '', expiration_hours: '24', message: '' });
    } catch (err) {
      setMsg(err.response?.data?.error || 'Share failed');
    }
  };

  const change = (e) => setData({ ...data, [e.target.name]: e.target.value });

  return (
    <div className="view-container">
      <h3>Share a File</h3>
      {files.length === 0 ? (
        <div className="empty">Upload files first to share them</div>
      ) : (
        <form onSubmit={submit} className="form">
          <div className="form-group">
            <label>Select File to Share</label>
            <select name="file_id" value={data.file_id} onChange={change} required>
              <option value="">Choose a file...</option>
              {files.map(f => (
                <option key={f.id} value={f.id}>
                  {f.filename} ({(f.size/1024/1024).toFixed(2)}MB)
                </option>
              ))}
            </select>
          </div>
          
          <div className="form-group">
            <label>Recipient Email Address</label>
            <input name="recipient_email" type="email" value={data.recipient_email} onChange={change} required />
          </div>
          
          <div className="form-group">
            <label>Link Expiration Time</label>
            <select name="expiration_hours" value={data.expiration_hours} onChange={change} required>
              <option value="1">1 Hour</option>
              <option value="6">6 Hours</option>
              <option value="24">1 Day</option>
              <option value="168">1 Week</option>
              <option value="720">1 Month</option>
            </select>
          </div>
          
          <div className="form-group">
            <label>Message (Optional)</label>
            <textarea name="message" placeholder="Add a personal message for the recipient..." value={data.message} onChange={change} rows="4" />
          </div>
          
          <button type="submit" className="submit-btn">
            📤 Share File
          </button>
        </form>
      )}
    </div>
  );
}

// Change Password View
function PasswordView({ token, setMsg }) {
  const [data, setData] = useState({ old_password: '', new_password: '', confirm_password: '' });

  const submit = async (e) => {
    e.preventDefault();
    if (data.new_password !== data.confirm_password) {
      setMsg('New passwords do not match!'); return;
    }
    try {
      await axios.post('/auth/change-password', data, { headers: { Authorization: `Bearer ${token}` } });
      setMsg('Password changed successfully!');
      setData({ old_password: '', new_password: '', confirm_password: '' });
    } catch (err) {
      setMsg(err.response?.data?.error || 'Failed to change password');
    }
  };

  const change = (e) => setData({ ...data, [e.target.name]: e.target.value });

  return (
    <div className="view-container">
      <h3>Change Password</h3>
      <form onSubmit={submit} className="password-form">
        <div className="form-group">
          <label>Current Password</label>
          <input name="old_password" type="password" value={data.old_password} onChange={change} required />
        </div>
        <div className="form-group">
          <label>New Password</label>
          <input name="new_password" type="password" value={data.new_password} onChange={change} required />
        </div>
        <div className="form-group">
          <label>Confirm New Password</label>
          <input name="confirm_password" type="password" value={data.confirm_password} onChange={change} required />
        </div>
        <button type="submit" className="submit-btn">Change Password</button>
      </form>
      <div className="password-requirements">
        <p><strong>Password Requirements:</strong></p>
        <ul>
          <li>At least 8 characters long</li>
          <li>One uppercase letter (A-Z)</li>
          <li>One lowercase letter (a-z)</li>
          <li>One number (0-9)</li>
          <li>One special character (!@#$%^&*)</li>
        </ul>
      </div>
    </div>
  );
}

// Public Share Component
function PublicShare({ token }) {
  const [info, setInfo] = useState(null);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const res = await axios.get(`/share/public/${token}`);
        setInfo(res.data);
      } catch {
        setMsg('Share not found or expired');
      }
    };
    load();
  }, []);

  const download = async () => {
    try {
      const res = await axios.get(`/share/public/${token}/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url; a.download = info.filename; a.click();
    } catch {
      setMsg('Download failed');
    }
  };

  if (msg) return <div className="public-share error">{msg}</div>;
  if (!info) return <div className="public-share">Loading...</div>;

  return (
    <div className="public-share">
      <h2>📁 Shared File</h2>
      <div className="file-card">
        <p><strong>File:</strong> {info.filename}</p>
        <p><strong>Size:</strong> {(info.size/1024/1024).toFixed(2)}MB</p>
        <p><strong>From:</strong> {info.sender}</p>
        <p><strong>Expires:</strong> {new Date(info.expires_at).toLocaleString()}</p>
        {info.message && <p><strong>Message:</strong> {info.message}</p>}
      </div>
      <button onClick={download} className="download-btn">Download File</button>
      {msg && <p>{msg}</p>}
    </div>
  );
}

export default App;