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

  useEffect(() => {
    const interceptor = axios.interceptors.request.use(config => {
      const currentToken = localStorage.getItem('token');
      if (currentToken) config.headers.Authorization = `Bearer ${currentToken}`;
      return config;
    });

    const responseInterceptor = axios.interceptors.response.use(
      response => response,
      error => {
        if (error.response?.status === 401) {
          localStorage.removeItem('token');
          setToken(null);
          setView('login');
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(interceptor);
      axios.interceptors.response.eject(responseInterceptor);
    };
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
        setMsg('Reset link sent to email');
        setTimeout(() => setView('login'), 2000);
      }
    } catch (err) {
      setMsg(err.response?.data?.error || 'Error occurred');
    }
  };

  const change = (e) => setData({ ...data, [e.target.name]: e.target.value });
  
  const handleDateChange = (e) => {
    if (e.target.value) {
      setData({ ...data, date_of_birth: e.target.value });
    }
  };

  return (
    <div className="auth-container">
      <h2>{view === 'register' ? 'Register' : view === 'forgot' ? 'Reset Password' : 'Login'}</h2>
      <form onSubmit={submit}>
        {view === 'register' && (
          <>
            <input name="first_name" placeholder="First Name" onChange={change} required />
            <input name="last_name" placeholder="Last Name" onChange={change} required />
            <input name="date_of_birth" type="date" onChange={handleDateChange} required />
            <input name="email" type="email" placeholder="Email" onChange={change} required />
            <input name="password" type="password" placeholder="Password" onChange={change} required />
            <input name="confirm_password" type="password" placeholder="Confirm Password" onChange={change} required />
          </>
        )}
        
        {view === 'login' && (
          <>
            <input name="email" type="email" placeholder="Email" onChange={change} required />
            <input name="password" type="password" placeholder="Password" onChange={change} required />
          </>
        )}

        {view === 'forgot' && (
          <input name="email" type="email" placeholder="Email" onChange={change} required />
        )}
        
        <button type="submit">
          {view === 'register' ? 'Register' : view === 'forgot' ? 'Send Reset' : 'Login'}
        </button>
      </form>
      
      {msg && <div className="message">{msg}</div>}
      
      <div className="links">
        {view === 'login' && (
          <>
            <button onClick={() => setView('register')}>Create Account</button>
            <button onClick={() => setView('forgot')}>Forgot Password</button>
          </>
        )}
        {view === 'register' && <button onClick={() => setView('login')}>Back to Login</button>}
        {view === 'forgot' && <button onClick={() => setView('login')}>Back to Login</button>}
      </div>
    </div>
  );
}

function ResetPassword({ token }) {
  const [data, setData] = useState({ token, new_password: '', confirm_password: '' });
  const [msg, setMsg] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    if (data.new_password !== data.confirm_password) {
      setMsg('Passwords do not match');
      return;
    }
    try {
      await axios.post('/auth/reset-password', data);
      setMsg('Password reset successful');
      setTimeout(() => window.location.href = '/', 2000);
    } catch (err) {
      setMsg(err.response?.data?.error || 'Reset failed');
    }
  };

  return (
    <div className="auth-container">
      <h2>Reset Password</h2>
      <form onSubmit={submit}>
        <input name="new_password" type="password" placeholder="New Password" 
               onChange={(e) => setData({...data, [e.target.name]: e.target.value})} required />
        <input name="confirm_password" type="password" placeholder="Confirm Password" 
               onChange={(e) => setData({...data, [e.target.name]: e.target.value})} required />
        <button type="submit">Reset Password</button>
      </form>
      {msg && <div className="message">{msg}</div>}
    </div>
  );
}

function Dashboard({ token, logout }) {
  const [view, setView] = useState('files');
  const [files, setFiles] = useState([]);
  const [shares, setShares] = useState([]);
  const [search, setSearch] = useState('');
  const [msg, setMsg] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    if (view === 'files') loadFiles();
    if (view === 'shares') loadShares();
  }, [view, search, currentPage]);

  const loadFiles = async () => {
    try {
      const res = await axios.get(`/files?search=${search}&page=${currentPage}`);
      setFiles(res.data.files);
      setTotalPages(res.data.pages);
    } catch (err) { setMsg('Error loading files'); }
  };

  const loadShares = async () => {
    try {
      const res = await axios.get('/share/my-shares');
      setShares(res.data.shares);
    } catch (err) { setMsg('Error loading shares'); }
  };

  const upload = async (e) => {
    const formData = new FormData();
    [...e.target.files].forEach(file => formData.append('files', file));
    try {
      await axios.post('/files/upload', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      setMsg('Upload successful');
      loadFiles();
    } catch (err) { setMsg('Upload failed'); }
  };

  const deleteFile = async (id) => {
    if (!window.confirm('Delete file?')) return;
    try {
      await axios.delete(`/files/${id}`);
      setMsg('File deleted');
      loadFiles();
    } catch (err) { setMsg('Delete failed'); }
  };

  const download = async (id, name) => {
    try {
      const res = await axios.get(`/files/${id}/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url; a.download = name; a.click();
      URL.revokeObjectURL(url);
    } catch (err) { setMsg('Download failed'); }
  };

  return (
    <div className="dashboard">
      <div className="header">
        <h1>File Share</h1>
        <div>
          {['files', 'shares', 'share', 'password'].map(v => (
            <button key={v} onClick={() => setView(v)} className={view === v ? 'active' : ''}>
              {v.charAt(0).toUpperCase() + v.slice(1)}
            </button>
          ))}
          <button onClick={logout}>Logout</button>
        </div>
      </div>

      {msg && <div className="message">{msg}</div>}

      {view === 'files' && <FilesView files={files} search={search} setSearch={setSearch} upload={upload} deleteFile={deleteFile} download={download} currentPage={currentPage} setCurrentPage={setCurrentPage} totalPages={totalPages} />}
      {view === 'shares' && <SharesView shares={shares} />}
      {view === 'share' && <ShareView setMsg={setMsg} files={files} />}
      {view === 'password' && <PasswordView setMsg={setMsg} />}
    </div>
  );
}

function FilesView({ files, search, setSearch, upload, deleteFile, download, currentPage, setCurrentPage, totalPages }) {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    setDragActive(e.type === "dragenter" || e.type === "dragover");
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files?.[0]) upload({ target: { files: e.dataTransfer.files } });
  };

  return (
    <div>
      <div className={`drag-area ${dragActive ? 'active' : ''}`}
           onDragEnter={handleDrag} onDragOver={handleDrag} onDragLeave={handleDrag} onDrop={handleDrop}
           onClick={() => document.getElementById('file-upload').click()}>
        <p>Drag & Drop Files or Click to Browse</p>
        <input type="file" multiple onChange={upload} id="file-upload" style={{ display: 'none' }} />
      </div>

      <input type="text" placeholder="Search files..." value={search} onChange={(e) => setSearch(e.target.value)} />
      
      <div className="files-list">
        {files.length === 0 ? (
          <p>No files uploaded yet</p>
        ) : (
          files.map(f => (
            <div key={f.id} className="file-item">
              <span>{f.filename} ({(f.size/1024/1024).toFixed(2)}MB)</span>
              <div>
                <button onClick={() => download(f.id, f.filename)}>Download</button>
                <button onClick={() => deleteFile(f.id)}>Delete</button>
              </div>
            </div>
          ))
        )}
      </div>

      {totalPages > 1 && (
        <div className="pagination">
          <button onClick={() => setCurrentPage(currentPage - 1)} disabled={currentPage === 1}>
            Previous
          </button>
          <span>Page {currentPage} of {totalPages}</span>
          <button onClick={() => setCurrentPage(currentPage + 1)} disabled={currentPage === totalPages}>
            Next
          </button>
        </div>
      )}
    </div>
  );
}

function SharesView({ shares }) {
  return (
    <div>
      <h3>My Shared Files</h3>
      {shares.length === 0 ? (
        <p>No shared files</p>
      ) : (
        shares.map(s => (
          <div key={s.id} className="share-item">
            <span>{s.file_name} → {s.recipient_email}</span>
            <span>{s.accessed ? 'Accessed' : 'Pending'} (Views: {s.access_count})</span>
          </div>
        ))
      )}
    </div>
  );
}

function ShareView({ setMsg, files }) {
  const [data, setData] = useState({ file_id: '', recipient_email: '', expiration_hours: '24', message: '' });

  const submit = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/share/create', data);
      setMsg('File shared successfully');
      setData({ file_id: '', recipient_email: '', expiration_hours: '24', message: '' });
    } catch (err) {
      setMsg(err.response?.data?.error || 'Share failed');
    }
  };

  return (
    <div>
      <h3>Share a File</h3>
      {files.length === 0 ? (
        <p>Upload files first</p>
      ) : (
        <form onSubmit={submit}>
          <select name="file_id" value={data.file_id} onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })} required>
            <option value="">Choose file...</option>
            {files.map(f => <option key={f.id} value={f.id}>{f.filename}</option>)}
          </select>
          
          <input name="recipient_email" type="email" placeholder="Recipient Email" value={data.recipient_email} 
                 onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })} required />
          
          <select name="expiration_hours" value={data.expiration_hours} 
                  onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })}>
            <option value="1">1 Hour</option>
            <option value="6">6 Hours</option>
            <option value="24">1 Day</option>
            <option value="168">1 Week</option>
            <option value="720">1 Month</option>
          </select>
          
          <textarea name="message" placeholder="Optional message" value={data.message} 
                    onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })} />
          
          <button type="submit">Share File</button>
        </form>
      )}
    </div>
  );
}

function PasswordView({ setMsg }) {
  const [data, setData] = useState({ old_password: '', new_password: '', confirm_password: '' });

  const submit = async (e) => {
    e.preventDefault();
    if (data.new_password !== data.confirm_password) {
      setMsg('Passwords do not match');
      return;
    }
    try {
      await axios.post('/auth/change-password', data);
      setMsg('Password changed successfully');
      setData({ old_password: '', new_password: '', confirm_password: '' });
    } catch (err) {
      setMsg(err.response?.data?.error || 'Failed to change password');
    }
  };

  return (
    <div>
      <h3>Change Password</h3>
      <form onSubmit={submit}>
        <input name="old_password" type="password" placeholder="Current Password" value={data.old_password} 
               onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })} required />
        <input name="new_password" type="password" placeholder="New Password" value={data.new_password} 
               onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })} required />
        <input name="confirm_password" type="password" placeholder="Confirm Password" value={data.confirm_password} 
               onChange={(e) => setData({ ...data, [e.target.name]: e.target.value })} required />
        <button type="submit">Change Password</button>
      </form>
    </div>
  );
}

function PublicShare({ token }) {
  const [info, setInfo] = useState(null);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    const load = async () => {
      try {
        const res = await axios.get(`/share/public/${token}`);
        setInfo(res.data);
      } catch (err) {
        setMsg('Share not found or expired');
      }
    };
    load();
  }, [token]);

  const download = async () => {
    try {
      const res = await axios.get(`/share/public/${token}/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement('a');
      a.href = url; a.download = info.filename; a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setMsg('Download failed');
    }
  };

  if (msg) return <div className="error">{msg}</div>;
  if (!info) return <div>Loading...</div>;

  return (
    <div className="public-share">
      <h2>Shared File</h2>
      <p>File: {info.filename}</p>
      <p>Size: {(info.size/1024/1024).toFixed(2)}MB</p>
      <p>From: {info.sender}</p>
      {info.message && <p>Message: {info.message}</p>}
      <button onClick={download}>Download File</button>
    </div>
  );
}

export default App;