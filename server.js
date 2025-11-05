require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');

const app = express();
app.use(bodyParser.json());

// CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }
  
  next();
});

const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const PLAYLIST_ID = process.env.SPOTIFY_PLAYLIST_ID;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SPOTIFY_AUTH_PASSWORD = process.env.SPOTIFY_AUTH_PASSWORD || 'spotify123';
const REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI || 'https://tropical-alvera-msorg-b735c0d5.koyeb.app/callback';

// Supabase configuration
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Validate required environment variables
if (!CLIENT_ID || !CLIENT_SECRET || !PLAYLIST_ID) {
  console.error('❌ Missing required Spotify environment variables:');
  if (!CLIENT_ID) console.error('  - SPOTIFY_CLIENT_ID');
  if (!CLIENT_SECRET) console.error('  - SPOTIFY_CLIENT_SECRET');
  if (!PLAYLIST_ID) console.error('  - SPOTIFY_PLAYLIST_ID');
  process.exit(1);
}

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error('❌ Missing required Supabase environment variables:');
  if (!SUPABASE_URL) console.error('  - SUPABASE_URL');
  if (!SUPABASE_ANON_KEY) console.error('  - SUPABASE_ANON_KEY');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Legacy variables for backward compatibility during migration
let submissions = [];
let blocked = [];
let tokens = {};
let users = [];

// Secure file loading functions
function loadSubmissions() {
  try {
    if (fs.existsSync('submissions.json')) {
      submissions = JSON.parse(fs.readFileSync('submissions.json'));
      console.log(`Loaded ${submissions.length} submissions`);
    } else {
      console.log('No submissions.json found - starting fresh');
      submissions = [];
    }
  } catch (error) {
    console.error('Error loading submissions:', error.message);
    submissions = [];
  }
}

function loadBlocked() {
  try {
    if (fs.existsSync('blocked.json')) {
      blocked = JSON.parse(fs.readFileSync('blocked.json'));
      console.log(`Loaded ${blocked.length} blocked links`);
    } else {
      console.log('No blocked.json found - starting fresh');
      blocked = [];
    }
  } catch (error) {
    console.error('Error loading blocked list:', error.message);
    blocked = [];
  }
}

function loadTokens() {
  try {
    if (fs.existsSync('tokens.json')) {
      tokens = JSON.parse(fs.readFileSync('tokens.json'));
      console.log('✅ Tokens loaded successfully');
    } else {
      console.log('ℹ️  No tokens.json found - will be created during Spotify OAuth');
      tokens = {};
    }
  } catch (error) {
    console.error('❌ Error loading tokens:', error.message);
    tokens = {};
  }
}

function loadUsers() {
  try {
    if (fs.existsSync('users.json')) {
      users = JSON.parse(fs.readFileSync('users.json'));
      console.log(`Loaded ${users.length} users`);
    } else {
      console.log('No users.json found - creating default admin user');
      users = [{
        id: crypto.randomUUID(),
        username: 'admin',
        password: ADMIN_PASSWORD,
        role: 'admin',
        isAdmin: true,
        created_at: new Date().toISOString(),
        created_by: 'system'
      }];
      saveUsers();
    }
  } catch (error) {
    console.error('Error loading users:', error.message);
    users = [{
      id: crypto.randomUUID(),
      username: 'admin',
      password: ADMIN_PASSWORD,
      role: 'admin',
      isAdmin: true,
      created_at: new Date().toISOString(),
      created_by: 'system'
    }];
    saveUsers();
  }
}

function saveUsers() {
  try {
    fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error saving users:', error.message);
  }
}

// Save all data files securely
function saveData() {
  try {
    fs.writeFileSync('submissions.json', JSON.stringify(submissions, null, 2));
    fs.writeFileSync('blocked.json', JSON.stringify(blocked, null, 2));
    
    if (tokens && (tokens.access_token || tokens.refresh_token)) {
      fs.writeFileSync('tokens.json', JSON.stringify(tokens, null, 2));
    }
    
  } catch (error) {
    console.error('Error saving data:', error.message);
  }
}

// ======================
// DATABASE HELPER FUNCTIONS
// ======================

// Submissions
async function getSubmissions(approved = null) {
  try {
    let query = supabase.from('submissions').select('*').order('created_at', { ascending: false });
    if (approved !== null) {
      query = query.eq('approved', approved);
    }
    const { data, error } = await query;
    if (error) throw error;
    return data || [];
  } catch (error) {
    console.error('Error getting submissions:', error.message);
    return [];
  }
}

async function createSubmission(submissionData) {
  try {
    const { data, error } = await supabase
      .from('submissions')
      .insert([submissionData])
      .select()
      .single();
    if (error) throw error;
    return data;
  } catch (error) {
    console.error('Error creating submission:', error.message);
    throw error;
  }
}

async function updateSubmission(id, updates) {
  try {
    const { data, error } = await supabase
      .from('submissions')
      .update(updates)
      .eq('id', id)
      .select()
      .single();
    if (error) throw error;
    return data;
  } catch (error) {
    console.error('Error updating submission:', error.message);
    throw error;
  }
}

async function deleteSubmission(id) {
  try {
    const { error } = await supabase
      .from('submissions')
      .delete()
      .eq('id', id);
    if (error) throw error;
    return true;
  } catch (error) {
    console.error('Error deleting submission:', error.message);
    throw error;
  }
}

// Blocked tracks
async function getBlockedTracks() {
  try {
    const { data, error } = await supabase
      .from('blocked_tracks')
      .select('*')
      .order('blocked_at', { ascending: false });
    if (error) throw error;
    return data || [];
  } catch (error) {
    console.error('Error getting blocked tracks:', error.message);
    return [];
  }
}

async function createBlockedTrack(trackData) {
  try {
    const { data, error } = await supabase
      .from('blocked_tracks')
      .insert([trackData])
      .select()
      .single();
    if (error) throw error;
    return data;
  } catch (error) {
    console.error('Error creating blocked track:', error.message);
    throw error;
  }
}

async function deleteBlockedTrack(spotifyLink) {
  try {
    const { error } = await supabase
      .from('blocked_tracks')
      .delete()
      .eq('spotify_link', spotifyLink);
    if (error) throw error;
    return true;
  } catch (error) {
    console.error('Error deleting blocked track:', error.message);
    throw error;
  }
}

async function isTrackBlocked(spotifyLink) {
  try {
    const { data, error } = await supabase
      .from('blocked_tracks')
      .select('id')
      .eq('spotify_link', spotifyLink)
      .single();
    if (error && error.code !== 'PGRST116') throw error;
    return !!data;
  } catch (error) {
    console.error('Error checking if track is blocked:', error.message);
    return false;
  }
}

// Users
async function getUserByUsername(username) {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username)
      .single();
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  } catch (error) {
    console.error('Error getting user by username:', error.message);
    return null;
  }
}

async function createUser(username, password, isAdmin = false) {
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('users')
      .insert([{ 
        username, 
        password_hash: passwordHash,
        is_admin: isAdmin 
      }])
      .select()
      .single();
    if (error) throw error;
    return data;
  } catch (error) {
    console.error('Error creating user:', error.message);
    throw error;
  }
}

async function getAllUsers() {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, username, is_admin, created_at')
      .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
  } catch (error) {
    console.error('Error getting all users:', error.message);
    return [];
  }
}

async function deleteUser(userId) {
  try {
    const { error } = await supabase
      .from('users')
      .delete()
      .eq('id', userId);
    if (error) throw error;
    return true;
  } catch (error) {
    console.error('Error deleting user:', error.message);
    throw error;
  }
}

async function updateUserAdminStatus(userId, isAdmin) {
  try {
    const { data, error } = await supabase
      .from('users')
      .update({ is_admin: isAdmin })
      .eq('id', userId)
      .select()
      .single();
    if (error) throw error;
    return data;
  } catch (error) {
    console.error('Error updating user admin status:', error.message);
    throw error;
  }
}

// Spotify tokens
async function getSpotifyTokens() {
  try {
    const { data, error } = await supabase
      .from('spotify_tokens')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();
    if (error && error.code !== 'PGRST116') throw error;
    return data;
  } catch (error) {
    console.error('Error getting Spotify tokens:', error.message);
    return null;
  }
}

async function saveSpotifyTokens(tokenData) {
  try {
    await supabase.from('spotify_tokens').delete().neq('id', '00000000-0000-0000-0000-000000000000');

    const { data, error } = await supabase
      .from('spotify_tokens')
      .insert([tokenData])
      .select()
      .single();
    if (error) throw error;
    return data;
  } catch (error) {
    console.error('Error saving Spotify tokens:', error.message);
    throw error;
  }
}

// Migration function to move data from JSON files to Supabase
async function migrateDataToSupabase() {
  console.log('🔄 Starting migration to Supabase...');

  try {
    // Migrate users
    if (users.length > 0) {
      console.log(`📤 Migrating ${users.length} users...`);
      for (const user of users) {
        const existingUser = await getUserByUsername(user.username);
        if (!existingUser) {
          await createUser(user.username, user.password, user.isAdmin || false);
          console.log(`✅ Migrated user: ${user.username}`);
        }
      }
    }

    // Migrate submissions
    if (submissions.length > 0) {
      console.log(`📤 Migrating ${submissions.length} submissions...`);
      for (const sub of submissions) {
        const submissionData = {
          username: sub.user || 'Anonymous',
          spotify_link: sub.link,
          track_id: extractSpotifyTrackId(sub.link),
          approved: sub.approved || false,
          created_at: new Date(sub.id).toISOString()
        };

        try {
          await createSubmission(submissionData);
          console.log(`✅ Migrated submission: ${sub.link}`);
        } catch (error) {
          if (error.code === '23505') {
            console.log(`⚠️  Submission already exists: ${sub.link}`);
          } else {
            console.error(`❌ Failed to migrate submission: ${sub.link}`, error.message);
          }
        }
      }
    }

    // Migrate blocked tracks
    if (blocked.length > 0) {
      console.log(`📤 Migrating ${blocked.length} blocked tracks...`);
      for (const link of blocked) {
        const trackData = {
          spotify_link: link,
          track_id: extractSpotifyTrackId(link),
          blocked_at: new Date().toISOString()
        };

        try {
          await createBlockedTrack(trackData);
          console.log(`✅ Migrated blocked track: ${link}`);
        } catch (error) {
          if (error.code === '23505') {
            console.log(`⚠️  Blocked track already exists: ${link}`);
          } else {
            console.error(`❌ Failed to migrate blocked track: ${link}`, error.message);
          }
        }
      }
    }

    // Migrate Spotify tokens
    if (tokens && (tokens.access_token || tokens.refresh_token)) {
      console.log('📤 Migrating Spotify tokens...');
      try {
        await saveSpotifyTokens({
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_at: tokens.expires_at ? new Date(tokens.expires_at).toISOString() : null,
          token_type: tokens.token_type || 'Bearer',
          scope: tokens.scope
        });
        console.log('✅ Migrated Spotify tokens');
      } catch (error) {
        console.error('❌ Failed to migrate Spotify tokens:', error.message);
      }
    }

    console.log('🎉 Migration to Supabase completed!');

    const backupDir = 'json_backup_' + Date.now();
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir);
    }

    const filesToBackup = ['submissions.json', 'blocked.json', 'tokens.json', 'users.json'];
    filesToBackup.forEach(file => {
      if (fs.existsSync(file)) {
        fs.copyFileSync(file, path.join(backupDir, file));
        console.log(`📁 Backed up ${file} to ${backupDir}/`);
      }
    });

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    throw error;
  }
}

// Initialize database and migrate data
async function initializeDatabase() {
  try {
    loadSubmissions();
    loadBlocked();
    loadTokens();
    loadUsers();

    const existingSubmissions = await getSubmissions();
    const existingBlocked = await getBlockedTracks();
    const { data: existingUsers } = await supabase.from('users').select('id').limit(1);

    const needsMigration = (
      (submissions.length > 0 && existingSubmissions.length === 0) ||
      (blocked.length > 0 && existingBlocked.length === 0) ||
      (users.length > 0 && existingUsers?.length === 0)
    );

    if (needsMigration) {
      await migrateDataToSupabase();
    } else {
      console.log('✅ Database already initialized, skipping migration');
    }

    const adminUser = await getUserByUsername('admin');
    if (!adminUser) {
      await createUser('admin', ADMIN_PASSWORD, true);
      console.log('✅ Created default admin user');
    } else if (!adminUser.is_admin) {
      await updateUserAdminStatus(adminUser.id, true);
      console.log('✅ Updated admin user with admin privileges');
    }

    const dbTokens = await getSpotifyTokens();
    if (dbTokens) {
      tokens = {
        access_token: dbTokens.access_token,
        refresh_token: dbTokens.refresh_token,
        expires_at: dbTokens.expires_at ? new Date(dbTokens.expires_at).getTime() : null,
        token_type: dbTokens.token_type,
        scope: dbTokens.scope
      };
      console.log('✅ Loaded Spotify tokens from database');
    }

    console.log('🚀 Database initialization complete');

  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    console.log('⚠️  Falling back to JSON file mode');
  }
}

// User authentication functions
async function authenticateUser(username, password) {
  try {
    const user = await getUserByUsername(username);
    if (!user) return null;

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (isValid) {
      return {
        id: user.id,
        username: user.username,
        role: user.is_admin ? 'admin' : 'user',
        isAdmin: user.is_admin,
        created_at: user.created_at
      };
    }
    return null;
  } catch (error) {
    console.error('Error authenticating user:', error);
    return null;
  }
}

async function createUserAccount(username, password, isAdmin = false, createdBy = null) {
  try {
    const newUser = await createUser(username, password, isAdmin);
    return {
      id: newUser.id,
      username: newUser.username,
      role: newUser.is_admin ? 'admin' : 'user',
      isAdmin: newUser.is_admin,
      created_at: newUser.created_at,
      created_by: createdBy || 'system'
    };
  } catch (error) {
    console.error('Error creating user account:', error);
    throw error;
  }
}

initializeDatabase();

// Session management
let sessions = new Map();

function createSession(user) {
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, {
    user,
    createdAt: Date.now()
  });
  return sessionId;
}

function getSessionUser(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;

  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    sessions.delete(sessionId);
    return null;
  }

  return session.user;
}

function requireAuth(req, res, next) {
  const sessionId = req.headers.authorization?.replace('Bearer ', '');
  const user = getSessionUser(sessionId);

  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const sessionId = req.headers.authorization?.replace('Bearer ', '');
  const user = getSessionUser(sessionId);

  if (!user || !user.isAdmin) {
    return res.status(401).json({ error: 'Admin access required' });
  }

  req.user = user;
  next();
}

function isSpotifyAuthNeeded() {
  return !tokens.access_token && !tokens.refresh_token;
}

async function refreshAccessToken() {
  const now = Date.now();
  
  if (tokens.access_token && tokens.expires_at && tokens.expires_at > now + 60000) {
    return tokens.access_token;
  }
  
  if (!tokens.refresh_token) {
    throw new Error('No refresh token stored! Spotify re-authentication required.');
  }

  const params = new URLSearchParams();
  params.append('grant_type', 'refresh_token');
  params.append('refresh_token', tokens.refresh_token);

  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: {
      Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error('Spotify refresh token error: ' + text);
  }

  const data = await res.json();

  tokens.access_token = data.access_token;
  tokens.expires_at = Date.now() + data.expires_in * 1000;
  if (data.refresh_token) tokens.refresh_token = data.refresh_token;

  try {
    await saveSpotifyTokens({
      access_token: data.access_token,
      refresh_token: data.refresh_token || tokens.refresh_token,
      expires_at: new Date(tokens.expires_at).toISOString(),
      token_type: data.token_type || 'Bearer',
      scope: data.scope
    });
  } catch (error) {
    console.error('Error saving tokens to database:', error);
    saveData();
  }

  return tokens.access_token;
}

async function addTrackToSpotifyPlaylist(trackId) {
  const accessToken = await refreshAccessToken();
  const url = `https://api.spotify.com/v1/playlists/${PLAYLIST_ID}/tracks`;
  const body = { uris: [`spotify:track:${trackId}`] };

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Spotify API error: ${text}`);
  }
}

function extractSpotifyTrackId(url) {
  const m = url.match(/open\.spotify\.com\/track\/([a-zA-Z0-9]+)/);
  return m ? m[1] : null;
}

async function getTrackInfo(trackId) {
  try {
    const accessToken = await refreshAccessToken();
    const res = await fetch(`https://api.spotify.com/v1/tracks/${trackId}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (res.ok) {
      const data = await res.json();
      return {
        name: data.name,
        artist: data.artists[0]?.name || 'Unknown',
        album: data.album?.name || 'Unknown',
        explicit: data.explicit || false,
        image: data.album?.images?.[0]?.url || null,
        duration_ms: data.duration_ms || 0,
        popularity: data.popularity || 0
      };
    }
  } catch (e) {
    console.error('Error fetching track info:', e);
  }
  return null;
}

async function searchSpotifyTracks(query, limit = 10) {
  try {
    const accessToken = await refreshAccessToken();
    const encodedQuery = encodeURIComponent(query);
    const res = await fetch(`https://api.spotify.com/v1/search?q=${encodedQuery}&type=track&limit=${limit}`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (res.ok) {
      const data = await res.json();
      return data.tracks.items.map(track => ({
        id: track.id,
        name: track.name,
        artist: track.artists[0]?.name || 'Unknown',
        album: track.album?.name || 'Unknown',
        explicit: track.explicit || false,
        image: track.album?.images?.[0]?.url || null,
        duration_ms: track.duration_ms || 0,
        popularity: track.popularity || 0,
        spotify_url: track.external_urls?.spotify || `https://open.spotify.com/track/${track.id}`
      }));
    }
  } catch (e) {
    console.error('Error searching Spotify tracks:', e);
  }
  return [];
}

// SPOTIFY OAUTH ROUTES

// Spotify authentication page
const spotifyAuthHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>beaDJ - Spotify Authentication</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        :root {
            --primary: #1db954;
            --primary-dark: #1ed760;
            --secondary: #191414;
            --danger: #e22134;
            --warning: #ff9800;
            --success: #4caf50;
            --background: #121212;
            --surface: #181818;
            --surface-light: #282828;
            --text-primary: #ffffff;
            --text-secondary: #b3b3b3;
            --text-muted: #535353;
            --border: #404040;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, var(--background) 0%, #0a0a0a 100%);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .auth-container {
            max-width: 500px;
            width: 100%;
            background: linear-gradient(135deg, var(--surface) 0%, var(--surface-light) 100%);
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border);
            text-align: center;
        }

        .auth-container h1 {
            margin: 0 0 20px 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5em;
            font-weight: 700;
        }

        .warning-message {
            background: rgba(255, 152, 0, 0.1);
            border: 1px solid rgba(255, 152, 0, 0.3);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            color: var(--warning);
        }

        .auth-message {
            font-size: 1.1em;
            margin: 20px 0;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .contact-info {
            background: rgba(29, 185, 84, 0.1);
            border: 1px solid rgba(29, 185, 84, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            font-size: 0.9em;
        }

        input {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 1px solid var(--border);
            border-radius: 8px;
            box-sizing: border-box;
            background: var(--background);
            color: var(--text-primary);
            font-size: 1em;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(29, 185, 84, 0.2);
        }

        button {
            width: 100%;
            padding: 15px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 1em;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin: 10px 0;
        }

        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }

        .spotify-btn {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }

        .spotify-btn:hover {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%);
        }

        .spotify-btn:disabled {
            background: var(--text-muted);
            cursor: not-allowed;
            transform: none;
        }

        .error {
            color: var(--danger);
            margin: 10px 0;
            padding: 10px;
            background: rgba(226, 33, 52, 0.1);
            border-radius: 6px;
            border: 1px solid rgba(226, 33, 52, 0.2);
        }

        .step-indicator {
            display: flex;
            justify-content: center;
            margin: 30px 0;
            gap: 10px;
        }

        .step {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background: var(--text-muted);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.9em;
        }

        .step.active {
            background: var(--primary);
        }

        .step.completed {
            background: var(--success);
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <h1>🎵 beaDJ</h1>
        
        <div class="warning-message">
            <strong>⚠️ Spotify Re-authentication Required</strong>
        </div>

        <div class="auth-message">
            The Spotify authentication tokens have expired or are missing. 
            Administrator access is required to re-authenticate with Spotify.
        </div>

        <div class="contact-info">
            <strong>📧 Please notify Moritz Breier</strong><br>
            Spotify authentication is needed to continue managing the playlist.
        </div>

        <div class="step-indicator">
            <div class="step active" id="step1">1</div>
            <div class="step" id="step2">2</div>
        </div>

        <div id="passwordStep">
            <input type="password" 
                   id="authPassword" 
                   placeholder="Enter Spotify authentication password"
                   onkeypress="if(event.key==='Enter') verifyPassword()">
            <button onclick="verifyPassword()" class="spotify-btn">🔐 Verify Access</button>
        </div>

        <div id="spotifyStep" style="display: none;">
            <p>Password verified! Click below to authenticate with Spotify:</p>
            <button onclick="authenticateSpotify()" class="spotify-btn">
                🎵 Authenticate with Spotify
            </button>
        </div>

        <div id="error" class="error" style="display: none;"></div>
    </div>

    <script>
        function showError(message) {
            const errorDiv = document.getElementById('error');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }

        function hideError() {
            document.getElementById('error').style.display = 'none';
        }

        async function verifyPassword() {
            const password = document.getElementById('authPassword').value;
            hideError();

            if (!password) {
                showError('Please enter the authentication password');
                return;
            }

            try {
                const res = await fetch('/spotify-auth/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });

                if (res.ok) {
                    // Update UI to show step 2
                    document.getElementById('step1').classList.add('completed');
                    document.getElementById('step1').classList.remove('active');
                    document.getElementById('step2').classList.add('active');
                    
                    document.getElementById('passwordStep').style.display = 'none';
                    document.getElementById('spotifyStep').style.display = 'block';
                } else {
                    showError('Invalid authentication password');
                }
            } catch (e) {
                showError('Authentication failed');
            }
        }

        function authenticateSpotify() {
            // Generate state parameter for security
            const state = Math.random().toString(36).substring(2, 15) + 
                         Math.random().toString(36).substring(2, 15);
            
            // Store state in sessionStorage
            sessionStorage.setItem('spotify_oauth_state', state);
            
            const scopes = 'playlist-modify-private playlist-modify-public';
            const authUrl = 'https://accounts.spotify.com/authorize?' +
                'response_type=code' +
                '&client_id=' + encodeURIComponent('${CLIENT_ID}') +
                '&scope=' + encodeURIComponent(scopes) +
                '&redirect_uri=' + encodeURIComponent('${REDIRECT_URI}') +
                '&state=' + encodeURIComponent(state);
            
            window.location.href = authUrl;
        }
    </script>
</body>
</html>
`;

// Spotify OAuth callback success page
const callbackSuccessHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>beaDJ - Authentication Successful</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #121212 0%, #0a0a0a 100%);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .success-container {
            max-width: 500px;
            width: 100%;
            background: linear-gradient(135deg, #181818 0%, #282828 100%);
            border-radius: 16px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.4);
            border: 1px solid #404040;
        }

        .success-icon {
            font-size: 4em;
            margin-bottom: 20px;
        }

        h1 {
            background: linear-gradient(135deg, #1db954 0%, #1ed760 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0 0 20px 0;
            font-size: 2em;
        }

        p {
            color: #b3b3b3;
            font-size: 1.1em;
            line-height: 1.6;
            margin: 20px 0;
        }

        .button {
            display: inline-block;
            background: linear-gradient(135deg, #1db954 0%, #1ed760 100%);
            color: white;
            text-decoration: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
            margin-top: 20px;
        }

        .button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
    </style>
</head>
<body>
    <div class="success-container">
        <div class="success-icon">✅</div>
        <h1>Authentication Successful!</h1>
        <p>Spotify authentication has been completed successfully. The beaDJ application can now manage the playlist.</p>
        <p>You can now close this page and return to the admin panel.</p>
        <a href="/admin" class="button">🎵 Go to Admin Panel</a>
    </div>
</body>
</html>
`;

// Spotify auth routes
app.get('/spotify-auth', (req, res) => {
  res.send(spotifyAuthHTML);
});

app.post('/spotify-auth/verify', (req, res) => {
  const { password } = req.body;
  if (password === SPOTIFY_AUTH_PASSWORD) {
    res.json({ status: 'verified' });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`
      <h1>Spotify Authentication Error</h1>
      <p>Error: ${error}</p>
      <a href="/spotify-auth">Try Again</a>
    `);
  }

  if (!code) {
    return res.status(400).send(`
      <h1>Authentication Failed</h1>
      <p>No authorization code received</p>
      <a href="/spotify-auth">Try Again</a>
    `);
  }

  try {
    // Exchange code for tokens
    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('redirect_uri', REDIRECT_URI);

    const tokenRes = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        Authorization: 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!tokenRes.ok) {
      const errorText = await tokenRes.text();
      throw new Error(`Token exchange failed: ${errorText}`);
    }

    const tokenData = await tokenRes.json();
    
    // Store tokens in memory
    tokens = {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_at: Date.now() + tokenData.expires_in * 1000,
      token_type: tokenData.token_type,
      scope: tokenData.scope
    };

    // Store tokens in database
    try {
      await saveSpotifyTokens({
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        expires_at: new Date(tokens.expires_at).toISOString(),
        token_type: tokenData.token_type,
        scope: tokenData.scope
      });
      console.log('✅ Spotify tokens saved to database');
    } catch (error) {
      console.error('Error saving tokens to database:', error);
      // Fallback to JSON file
      saveData();
    }

    console.log('✅ Spotify authentication successful');

    res.send(callbackSuccessHTML);
  } catch (error) {
    console.error('Spotify OAuth error:', error);
    res.status(500).send(`
      <h1>Authentication Error</h1>
      <p>Failed to complete Spotify authentication: ${error.message}</p>
      <a href="/spotify-auth">Try Again</a>
    `);
  }
});

// ENHANCED ADMIN PANEL HTML with Spotify Auth Check
const adminPanelHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>beaDJ - Admin Panel</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        :root {
            --primary: #1db954;
            --primary-dark: #1ed760;
            --secondary: #191414;
            --danger: #e22134;
            --warning: #ff9800;
            --success: #4caf50;
            --background: #121212;
            --surface: #181818;
            --surface-light: #282828;
            --text-primary: #ffffff;
            --text-secondary: #b3b3b3;
            --text-muted: #535353;
            --border: #404040;
            --explicit: #e22134;
        }

        * {
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, var(--background) 0%, #0a0a0a 100%);
            color: var(--text-primary);
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        .header {
            background: linear-gradient(135deg, var(--surface) 0%, var(--surface-light) 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .header h1 {
            margin: 0;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5em;
            font-weight: 700;
        }

        .header-actions {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }

        .user-info {
            background: rgba(29, 185, 84, 0.1);
            border: 1px solid rgba(29, 185, 84, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .role-badge {
            background: var(--primary);
            color: var(--secondary);
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .role-badge.admin {
            background: var(--warning);
        }

        .spotify-auth-warning {
            background: linear-gradient(135deg, rgba(255, 152, 0, 0.1) 0%, rgba(255, 152, 0, 0.05) 100%);
            border: 1px solid rgba(255, 152, 0, 0.3);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
        }

        .spotify-auth-warning h3 {
            color: var(--warning);
            margin: 0 0 15px 0;
            font-size: 1.2em;
        }

        .spotify-auth-warning p {
            color: var(--text-secondary);
            margin: 10px 0;
        }

        .section {
            background: linear-gradient(135deg, var(--surface) 0%, var(--surface-light) 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
        }

        .section h2 {
            margin: 0 0 25px 0;
            color: var(--text-primary);
            font-size: 1.5em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .submission {
            border: 1px solid var(--border);
            padding: 25px;
            margin: 15px 0;
            border-radius: 12px;
            background: linear-gradient(135deg, var(--background) 0%, #1a1a1a 100%);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .submission:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
        }

        .submission.approved {
            border-color: var(--success);
            background: linear-gradient(135deg, rgba(76, 175, 80, 0.1) 0%, rgba(76, 175, 80, 0.05) 100%);
        }

        .submission.blocked {
            border-color: var(--danger);
            background: linear-gradient(135deg, rgba(226, 33, 52, 0.1) 0%, rgba(226, 33, 52, 0.05) 100%);
        }

        .submission-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .submission-info {
            flex: 1;
            min-width: 300px;
        }

        .submission-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .track-info {
            background: rgba(255, 255, 255, 0.08);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid var(--primary);
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .track-image {
            width: 60px;
            height: 60px;
            border-radius: 6px;
            object-fit: cover;
            background: var(--surface-light);
        }

        .track-details {
            flex: 1;
        }

        .track-name {
            font-weight: 600;
            color: #ffffff;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .track-artist {
            color: #e0e0e0;
            font-size: 0.9em;
        }

        .explicit-badge {
            background: var(--explicit);
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .track-meta {
            display: flex;
            gap: 15px;
            margin-top: 8px;
            font-size: 0.8em;
            color: #cccccc;
        }

        button {
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.9em;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }

        button:disabled {
            background: var(--text-muted) !important;
            cursor: not-allowed;
            transform: none;
            opacity: 0.6;
        }

        .approve {
            background: linear-gradient(135deg, var(--success) 0%, #66bb6a 100%);
            color: white;
        }

        .approve:hover:not(:disabled) {
            background: linear-gradient(135deg, #66bb6a 0%, var(--success) 100%);
        }

        .block {
            background: linear-gradient(135deg, var(--danger) 0%, #ef5350 100%);
            color: white;
        }

        .block:hover:not(:disabled) {
            background: linear-gradient(135deg, #ef5350 0%, var(--danger) 100%);
        }

        .unblock {
            background: linear-gradient(135deg, var(--warning) 0%, #ffb74d 100%);
            color: white;
        }

        .unblock:hover:not(:disabled) {
            background: linear-gradient(135deg, #ffb74d 0%, var(--warning) 100%);
        }

        .primary-btn {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }

        .primary-btn:hover:not(:disabled) {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 100%);
        }

        .secondary-btn {
            background: linear-gradient(135deg, var(--surface-light) 0%, #3a3a3a 100%);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }

        .secondary-btn:hover:not(:disabled) {
            background: linear-gradient(135deg, #3a3a3a 0%, var(--surface-light) 100%);
        }

        .error {
            color: var(--danger);
            margin: 10px 0;
            padding: 10px;
            background: rgba(226, 33, 52, 0.1);
            border-radius: 6px;
            border: 1px solid rgba(226, 33, 52, 0.2);
        }

        .success {
            color: var(--success);
            margin: 10px 0;
            padding: 10px;
            background: rgba(76, 175, 80, 0.1);
            border-radius: 6px;
            border: 1px solid rgba(76, 175, 80, 0.2);
        }

        .login-form {
            max-width: 400px;
            margin: 100px auto;
            padding: 40px;
            background: linear-gradient(135deg, var(--surface) 0%, var(--surface-light) 100%);
            border-radius: 16px;
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.4);
            border: 1px solid var(--border);
        }

        .login-form h2 {
            text-align: center;
            margin-bottom: 30px;
            color: var(--text-primary);
        }

        input {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 1px solid var(--border);
            border-radius: 8px;
            box-sizing: border-box;
            background: var(--background);
            color: var(--text-primary);
            font-size: 1em;
        }

        input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(29, 185, 84, 0.2);
        }

        .loading {
            color: var(--text-muted);
            font-style: italic;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            color: white;
        }

        .stat-number {
            font-size: 2em;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }

        .block-link-form {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: end;
            margin-bottom: 20px;
        }

        @media (max-width: 768px) {
            body {
                padding: 10px;
            }

            .header {
                padding: 20px;
                flex-direction: column;
                gap: 20px;
            }

            .header h1 {
                font-size: 2em;
            }

            .section {
                padding: 20px;
            }

            .submission {
                padding: 20px;
            }

            .submission-header {
                flex-direction: column;
                align-items: stretch;
            }

            .track-info {
                flex-direction: column;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <div id="loginForm" class="login-form">
        <h2>🎵 beaDJ Dashboard</h2>
        <input type="text" id="username" placeholder="Username">
        <input type="password" id="password" placeholder="Password">
        <button id="loginButton" class="primary-btn" style="width: 100%; padding: 15px;">Login</button>
        <div id="loginError" class="error" style="display: none;"></div>
    </div>

    <div id="dashboardPanel" style="display: none;">
        <div class="container">
            <div class="header">
                <h1 id="dashboardTitle">🎵 beaDJ Dashboard</h1>
                <div class="header-actions">
                    <div style="display: flex; align-items: center; gap: 0.5rem; margin-right: 1rem;">
                        <span style="color: var(--text-muted); font-size: 0.875rem;">🌐</span>
                        <select id="adminLanguageSelect" style="background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 4px; padding: 0.25rem 0.5rem; font-size: 0.875rem;">
                            <option value="de">Deutsch</option>
                            <option value="en">English</option>
                        </select>
                    </div>
                    <button id="refreshButton" class="primary-btn">🔄 <span id="refreshText">Refresh</span></button>
                    <button id="spotifyCheckBtn" class="secondary-btn" style="display: none;">🎵 Check Spotify</button>
                    <button id="logoutButton" class="block">🚪 <span id="logoutText">Logout</span></button>
                </div>
            </div>

            <div class="user-info">
                <strong>👤 Logged in as:</strong> <span id="currentUser"></span>
                <span id="userRole" class="role-badge"></span>
            </div>

            <div id="spotifyAuthWarning" class="spotify-auth-warning" style="display: none;">
                <h3>⚠️ Spotify Authentication Required</h3>
                <p>Spotify authentication is needed to approve songs and manage the playlist.</p>
                <p><strong>Please contact an administrator</strong> - Administrator access required</p>
                <div id="spotifyAuthButton" style="display: none;">
                    <button class="primary-btn" onclick="window.open('/spotify-auth', '_blank')">
                        🔐 Re-authenticate Spotify
                    </button>
                </div>
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="pendingCount">0</div>
                    <div class="stat-label">Pending</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="approvedCount">0</div>
                    <div class="stat-label">Approved</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="blockedCount">0</div>
                    <div class="stat-label">Blocked</div>
                </div>
            </div>

            <div class="section" id="userManagementSection" style="display: none;">
                <h2>👥 User Management</h2>
                <div style="margin-bottom: 20px;">
                    <h3>Create New User</h3>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: end;">
                        <div>
                            <input type="text" id="newUsername" placeholder="Username" style="width: 200px;">
                        </div>
                        <div>
                            <input type="password" id="newPassword" placeholder="Password" style="width: 200px;">
                        </div>
                        <button id="createUserButton" class="primary-btn">➕ Create User</button>
                    </div>
                    <div id="createUserError" class="error" style="display: none;"></div>
                    <div id="createUserSuccess" class="success" style="display: none;"></div>
                </div>
                <div id="usersList"></div>
            </div>

            <div class="section">
                <h2 id="pendingTitle">⏳ Pending Submissions</h2>
                <div id="pendingSubmissions"></div>
            </div>

            <div class="section">
                <h2 id="approvedTitle">✅ Approved Submissions</h2>
                <div id="approvedSubmissions"></div>
            </div>

            <div class="section">
                <h2 id="blockedTitle">🚫 Blocked Links</h2>
                <div class="block-link-form">
                    <div style="margin-bottom: 1rem;">
                        <input type="text" id="blockSearchQuery" placeholder="Search for songs to block..." style="width: 300px; margin-right: 10px;">
                        <button id="searchToBlockButton" class="approve">🔍 <span id="searchText">Search</span></button>
                    </div>
                    <div id="blockSearchResults" style="display: none; margin-bottom: 1rem; max-height: 300px; overflow-y: auto; border: 1px solid #374151; border-radius: 8px; padding: 1rem; background: #1f2937;"></div>
                    <div style="border-top: 1px solid var(--border); padding-top: 1rem;">
                        <input type="text" id="newBlockLink" placeholder="Or enter Spotify link directly to block" style="width: 300px;">
                        <button id="blockLinkButton" class="block">🚫 <span id="blockText">Block Link</span></button>
                    </div>
                </div>
                <div id="blockLinkError" class="error" style="display: none;"></div>
                <div id="blockLinkSuccess" class="success" style="display: none;"></div>
                <div id="blockedLinks"></div>
            </div>
        </div>
    </div>

    <script>
        // Internationalization for admin panel
        const adminTranslations = {
            de: {
                // Login
                loginTitle: 'Admin Dashboard',
                passwordPlaceholder: 'Admin-Passwort eingeben',
                loginButton: 'Anmelden',
                wrongPassword: 'Falsches Passwort',

                // Navigation
                pendingSubmissions: 'Ausstehende Einreichungen',
                approvedSubmissions: 'Genehmigte Einreichungen',
                blockedLinks: 'Blockierte Links',
                userManagement: 'Benutzerverwaltung',

                // Actions
                approve: 'Genehmigen',
                disapprove: 'Ablehnen',
                block: 'Blockieren',
                unblock: 'Entsperren',
                delete: 'Löschen',
                refresh: 'Aktualisieren',
                logout: 'Abmelden',
                search: 'Suchen',

                // Messages
                noSubmissions: 'Keine Einreichungen vorhanden',
                noApproved: 'Noch keine genehmigten Einreichungen',
                noBlocked: 'Keine blockierten Links',
                trackBlocked: 'Track erfolgreich blockiert',
                searchForSongs: 'Nach Songs zum Blockieren suchen...',
                orEnterLink: 'Oder Spotify Link direkt eingeben',

                // User info
                user: 'Benutzer',
                link: 'Link',
                submitted: 'Eingereicht',
                approved: 'Genehmigt',

                // Language
                language: 'Sprache'
            },
            en: {
                // Login
                loginTitle: 'Admin Dashboard',
                passwordPlaceholder: 'Enter admin password',
                loginButton: 'Login',
                wrongPassword: 'Wrong password',

                // Navigation
                pendingSubmissions: 'Pending Submissions',
                approvedSubmissions: 'Approved Submissions',
                blockedLinks: 'Blocked Links',
                userManagement: 'User Management',

                // Actions
                approve: 'Approve',
                disapprove: 'Disapprove',
                block: 'Block',
                unblock: 'Unblock',
                'delete': 'Delete',
                refresh: 'Refresh',
                logout: 'Logout',
                search: 'Search',

                // Messages
                noSubmissions: 'No submissions available',
                noApproved: 'No approved submissions yet',
                noBlocked: 'No blocked links',
                trackBlocked: 'Track blocked successfully',
                searchForSongs: 'Search for songs to block...',
                orEnterLink: 'Or enter Spotify link directly',

                // User info
                user: 'User',
                link: 'Link',
                submitted: 'Submitted',
                approved: 'Approved',

                // Language
                language: 'Language'
            }
        };

        // Helper function for translations
        const adminT = (key, lang = 'de') => {
            return adminTranslations[lang]?.[key] || adminTranslations['en'][key] || key;
        };

        let sessionToken = localStorage.getItem('dashboardSession');
        let currentUser = null;
        let spotifyAuthRequired = false;
        let adminLanguage = localStorage.getItem('adminLanguage') || (navigator.language.startsWith('de') ? 'de' : 'en');

        // Language change function
        function changeAdminLanguage(newLang) {
            adminLanguage = newLang;
            localStorage.setItem('adminLanguage', newLang);
            updateAdminTexts();
        }

        // Update all admin panel texts
        function updateAdminTexts() {
            // Update titles and headers
            const dashboardTitle = document.getElementById('dashboardTitle');
            if (dashboardTitle) dashboardTitle.textContent = '🎵 beaDJ ' + adminT('loginTitle', adminLanguage);

            const pendingTitle = document.getElementById('pendingTitle');
            if (pendingTitle) pendingTitle.textContent = '⏳ ' + adminT('pendingSubmissions', adminLanguage);

            const approvedTitle = document.getElementById('approvedTitle');
            if (approvedTitle) approvedTitle.textContent = '✅ ' + adminT('approvedSubmissions', adminLanguage);

            const blockedTitle = document.getElementById('blockedTitle');
            if (blockedTitle) blockedTitle.textContent = '🚫 ' + adminT('blockedLinks', adminLanguage);

            // Update button texts
            const refreshText = document.getElementById('refreshText');
            if (refreshText) refreshText.textContent = adminT('refresh', adminLanguage);

            const logoutText = document.getElementById('logoutText');
            if (logoutText) logoutText.textContent = adminT('logout', adminLanguage);

            const searchText = document.getElementById('searchText');
            if (searchText) searchText.textContent = adminT('search', adminLanguage);

            const blockText = document.getElementById('blockText');
            if (blockText) blockText.textContent = adminT('block', adminLanguage) + ' Link';

            // Update placeholders
            const blockSearchQuery = document.getElementById('blockSearchQuery');
            if (blockSearchQuery) blockSearchQuery.placeholder = adminT('searchForSongs', adminLanguage);

            const newBlockLink = document.getElementById('newBlockLink');
            if (newBlockLink) newBlockLink.placeholder = adminT('orEnterLink', adminLanguage);
        }

        function escapeForJS(str) {
            if (!str) return '';
            return str.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\\n/g, '\\\\n');
        }

        document.addEventListener('DOMContentLoaded', function() {
            const passwordField = document.getElementById('password');
            const blockLinkField = document.getElementById('newBlockLink');
            const blockSearchField = document.getElementById('blockSearchQuery');
            const searchToBlockButton = document.getElementById('searchToBlockButton');
            const loginButton = document.getElementById('loginButton');
            const refreshButton = document.getElementById('refreshButton');
            const logoutButton = document.getElementById('logoutButton');
            const createUserButton = document.getElementById('createUserButton');
            const spotifyCheckButton = document.getElementById('spotifyCheckBtn');

            if (passwordField) {
                passwordField.addEventListener('keypress', function(event) {
                    if (event.key === 'Enter') {
                        login();
                    }
                });
            }

            if (blockLinkField) {
                blockLinkField.addEventListener('keypress', function(event) {
                    if (event.key === 'Enter') {
                        blockManualLink();
                    }
                });
            }

            if (blockSearchField) {
                blockSearchField.addEventListener('keypress', function(event) {
                    if (event.key === 'Enter') {
                        searchTracksToBlock();
                    }
                });
            }

            if (searchToBlockButton) {
                searchToBlockButton.addEventListener('click', searchTracksToBlock);
            }

            const adminLanguageSelect = document.getElementById('adminLanguageSelect');
            if (adminLanguageSelect) {
                adminLanguageSelect.value = adminLanguage;
                adminLanguageSelect.addEventListener('change', function(e) {
                    changeAdminLanguage(e.target.value);
                });
            }

            if (loginButton) {
                loginButton.addEventListener('click', login);
            }

            if (refreshButton) {
                refreshButton.addEventListener('click', loadData);
            }

            if (logoutButton) {
                logoutButton.addEventListener('click', logout);
            }

            if (createUserButton) {
                createUserButton.addEventListener('click', createUser);
            }

            if (spotifyCheckButton) {
                spotifyCheckButton.addEventListener('click', checkSpotifyAuth);
            }

            if (sessionToken) {
                checkSession();
            }
        });

        async function checkSession() {
            try {
                const res = await fetch('/dashboard/verify', {
                    headers: { 'Authorization': 'Bearer ' + sessionToken }
                });
                if (res.ok) {
                    const data = await res.json();
                    currentUser = data.user;
                    showDashboard();
                } else {
                    localStorage.removeItem('dashboardSession');
                    sessionToken = null;
                }
            } catch (e) {
                localStorage.removeItem('dashboardSession');
                sessionToken = null;
            }
        }

        async function checkSpotifyAuth() {
            try {
                const res = await apiCall('/admin/spotify-status');
                if (res && res.ok) {
                    const data = await res.json();
                    spotifyAuthRequired = data.authRequired;
                    updateSpotifyWarning();
                }
            } catch (e) {
                console.error('Error checking Spotify auth:', e);
            }
        }

        function updateSpotifyWarning() {
            const warning = document.getElementById('spotifyAuthWarning');
            const authButton = document.getElementById('spotifyAuthButton');

            if (spotifyAuthRequired) {
                warning.style.display = 'block';
                if (currentUser && currentUser.isAdmin) {
                    authButton.style.display = 'block';
                } else {
                    authButton.style.display = 'none';
                }
                document.querySelectorAll('.approve').forEach(btn => {
                    btn.disabled = true;
                    btn.title = 'Spotify authentication required';
                });
            } else {
                warning.style.display = 'none';
                authButton.style.display = 'none';
                document.querySelectorAll('.approve').forEach(btn => {
                    btn.disabled = false;
                    btn.title = '';
                });
            }
        }

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('loginError');

            errorDiv.style.display = 'none';

            if (!username || !password) {
                errorDiv.textContent = 'Please enter username and password';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                const res = await fetch('/dashboard/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                if (res.ok) {
                    const data = await res.json();
                    sessionToken = data.token;
                    currentUser = data.user;
                    localStorage.setItem('dashboardSession', sessionToken);
                    showDashboard();
                } else {
                    const errorData = await res.json().catch(() => ({ error: 'Invalid credentials' }));
                    errorDiv.textContent = errorData.error || 'Login failed';
                    errorDiv.style.display = 'block';
                }
            } catch (e) {
                console.error('Login error:', e);
                errorDiv.textContent = 'Login failed: ' + e.message;
                errorDiv.style.display = 'block';
            }
        }

        function logout() {
            localStorage.removeItem('dashboardSession');
            sessionToken = null;
            currentUser = null;
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('dashboardPanel').style.display = 'none';
        }

        function showDashboard() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('dashboardPanel').style.display = 'block';

            document.getElementById('currentUser').textContent = currentUser ? currentUser.username : 'Unknown';
            const roleElement = document.getElementById('userRole');
            if (currentUser) {
                roleElement.textContent = currentUser.role;
                roleElement.className = 'role-badge' + (currentUser.isAdmin ? ' admin' : '');
            }

            // Initialize language
            updateAdminTexts();

            updateUIBasedOnRole();
            loadData();
            checkSpotifyAuth();
        }

        function updateUIBasedOnRole() {
            const isAdmin = currentUser && currentUser.isAdmin;
            document.getElementById('userManagementSection').style.display = isAdmin ? 'block' : 'none';
            document.getElementById('spotifyCheckBtn').style.display = isAdmin ? 'inline-block' : 'none';
        }

        async function apiCall(url, options = {}) {
            const res = await fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Authorization': 'Bearer ' + sessionToken,
                    'Content-Type': 'application/json'
                }
            });

            if (res.status === 401) {
                logout();
                return null;
            }

            return res;
        }

        function formatDuration(ms) {
            const minutes = Math.floor(ms / 60000);
            const seconds = Math.floor((ms % 60000) / 1000);
            return minutes + ':' + seconds.toString().padStart(2, '0');
        }

        async function loadUsers() {
            if (!currentUser || !currentUser.isAdmin) return;

            try {
                const res = await apiCall('/dashboard/users');
                if (res && res.ok) {
                    const users = await res.json();
                    displayUsers(users);
                }
            } catch (e) {
                console.error('Error loading users:', e);
            }
        }

        function displayUsers(users) {
            const container = document.getElementById('usersList');
            if (users.length === 0) {
                container.innerHTML = '<div class="empty-state">👥 No users created yet</div>';
                return;
            }

            container.innerHTML = '';
            users.forEach(user => {
                const div = document.createElement('div');
                div.className = 'submission';
                div.innerHTML =
                    '<div class="submission-header">' +
                        '<div class="submission-info">' +
                            '<strong>👤 Username:</strong> ' + escapeForJS(user.username) + '<br>' +
                            '<strong>🔑 Role:</strong> ' + escapeForJS(user.role) + '<br>' +
                            '<strong>📅 Created:</strong> ' + new Date(user.created_at).toLocaleString() + '<br>' +
                            '<strong>👨‍💼 Created by:</strong> ' + escapeForJS(user.created_by) +
                        '</div>' +
                        '<div class="submission-actions">' +
                            '<button class="block delete-user-btn" data-user-id="' + escapeForJS(user.id) + '" data-username="' + escapeForJS(user.username) + '">🗑️ Delete</button>' +
                        '</div>' +
                    '</div>';
                container.appendChild(div);
            });

            document.querySelectorAll('.delete-user-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const userId = this.getAttribute('data-user-id');
                    const username = this.getAttribute('data-username');
                    deleteUser(userId, username);
                });
            });
        }

        async function createUser() {
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            const errorDiv = document.getElementById('createUserError');
            const successDiv = document.getElementById('createUserSuccess');

            errorDiv.style.display = 'none';
            successDiv.style.display = 'none';

            if (!username || !password) {
                errorDiv.textContent = 'Username and password are required';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                const res = await apiCall('/dashboard/users', {
                    method: 'POST',
                    body: JSON.stringify({ username, password })
                });

                if (res && res.ok) {
                    const newUser = await res.json();
                    successDiv.textContent = 'User "' + escapeForJS(newUser.username) + '" created successfully';
                    successDiv.style.display = 'block';

                    document.getElementById('newUsername').value = '';
                    document.getElementById('newPassword').value = '';
                    loadUsers();
                } else {
                    const error = await res.json();
                    errorDiv.textContent = error.error || 'Failed to create user';
                    errorDiv.style.display = 'block';
                }
            } catch (e) {
                errorDiv.textContent = 'Error creating user';
                errorDiv.style.display = 'block';
            }
        }

        async function deleteUser(userId, username) {
            if (!confirm('Are you sure you want to delete user "' + escapeForJS(username) + '"?')) {
                return;
            }

            try {
                const res = await apiCall('/dashboard/users/' + encodeURIComponent(userId), {
                    method: 'DELETE'
                });

                if (res && res.ok) {
                    loadUsers();
                } else {
                    alert('Failed to delete user');
                }
            } catch (e) {
                alert('Error deleting user');
            }
        }

        async function loadData() {
            try {
                const [pendingRes, approvedRes, blockedRes] = await Promise.all([
                    apiCall('/admin/pending'),
                    apiCall('/admin/approved'),
                    apiCall('/admin/blocked')
                ]);

                if (pendingRes && approvedRes && blockedRes) {
                    const pending = await pendingRes.json();
                    const approved = await approvedRes.json();
                    const blocked = await blockedRes.json();

                    document.getElementById('pendingCount').textContent = pending.length;
                    document.getElementById('approvedCount').textContent = approved.length;
                    document.getElementById('blockedCount').textContent = blocked.length;

                    displayPending(pending);
                    displayApproved(approved);
                    displayBlocked(blocked);
                }
            } catch (e) {
                console.error('Error loading data:', e);
            }
        }

        function displayPending(submissions) {
            const container = document.getElementById('pendingSubmissions');
            container.innerHTML = '';

            if (submissions.length === 0) {
                container.innerHTML = '<div class="empty-state">🎵 ' + adminT('noSubmissions', adminLanguage) + '</div>';
                return;
            }

            submissions.forEach(sub => {
                const disabledAttr = spotifyAuthRequired ? 'disabled title="Spotify authentication required"' : '';
                const encodedLink = encodeURIComponent(sub.link);
                const div = document.createElement('div');
                div.className = 'submission';
                div.innerHTML =
                    '<div class="submission-header">' +
                        '<div class="submission-info">' +
                            '<strong>👤 User:</strong> ' + escapeForJS(sub.user || 'Anonymous') + '<br>' +
                            '<strong>🔗 Link:</strong> <a href="' + escapeForJS(sub.link) + '" target="_blank" style="color: var(--primary);">' + escapeForJS(sub.link) + '</a><br>' +
                            '<strong>📅 Submitted:</strong> ' + new Date(sub.id).toLocaleString() +
                        '</div>' +
                        '<div class="submission-actions">' +
                            '<button class="approve approve-btn" data-sub-id="' + sub.id + '" ' + disabledAttr + '>✅ Approve</button>' +
                            '<button class="block disapprove-btn" data-link="' + encodedLink + '">🚫 Block</button>' +
                        '</div>' +
                    '</div>' +
                    '<div id="track-' + sub.id + '" class="track-info loading">🎵 Loading track info...</div>';
                container.appendChild(div);

                (async () => {
                    const trackDiv = document.getElementById('track-' + sub.id);
                    const trackInfo = await getTrackInfo(sub.link);
                    if (!trackDiv) return;

                    if (!trackInfo) {
                        trackDiv.innerHTML = '❌ Could not load track info';
                        trackDiv.classList.remove('loading');
                        return;
                    }

                    const explicitBadge = trackInfo.explicit ? '<span class="explicit-badge">Explicit</span>' : '';
                    const image = trackInfo.image ?
                        '<img src="' + escapeForJS(trackInfo.image) + '" alt="Album art" class="track-image">' :
                        '<div class="track-image" style="display: flex; align-items: center; justify-content: center; background: var(--surface-light); color: var(--text-muted);">🎵</div>';

                    trackDiv.innerHTML =
                        image +
                        '<div class="track-details">' +
                            '<div class="track-name">🎵 ' + escapeForJS(trackInfo.name) + ' ' + explicitBadge + '</div>' +
                            '<div class="track-artist">👨‍🎤 ' + escapeForJS(trackInfo.artist) + '</div>' +
                            '<div class="track-meta">' +
                                '<span>📀 ' + escapeForJS(trackInfo.album) + '</span>' +
                                '<span>⏱️ ' + formatDuration(trackInfo.duration_ms) + '</span>' +
                                '<span>📊 ' + trackInfo.popularity + '% popularity</span>' +
                            '</div>' +
                        '</div>';

                    trackDiv.classList.remove('loading');
                    if (trackInfo.explicit) trackDiv.style.borderColor = 'var(--explicit)';
                })();
            });

            document.querySelectorAll('.approve-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const subId = this.getAttribute('data-sub-id');
                    approveSubmission(subId);
                });
            });

            document.querySelectorAll('.disapprove-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const link = this.getAttribute('data-link');
                    blockLink(link);
                });
            });
        }

        async function blockLink(encodedLink) {
            const link = decodeURIComponent(encodedLink);
            try {
                const res = await apiCall('/admin/block', {
                    method: 'POST',
                    body: JSON.stringify({ link })
                });
                if (res && res.ok) {
                    loadData();
                } else {
                    alert('Error disapproving link');
                }
            } catch (e) {
                alert('Error disapproving link');
            }
        }

        async function blockManualLink() {
            const link = document.getElementById('newBlockLink').value;
            const errorDiv = document.getElementById('blockLinkError');
            const successDiv = document.getElementById('blockLinkSuccess');

            errorDiv.style.display = 'none';
            successDiv.style.display = 'none';

            if (!link) {
                errorDiv.textContent = 'Please enter a Spotify link';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                const res = await apiCall('/admin/block', {
                    method: 'POST',
                    body: JSON.stringify({ link })
                });

                if (res && res.ok) {
                    successDiv.textContent = 'Link blocked successfully';
                    successDiv.style.display = 'block';
                    document.getElementById('newBlockLink').value = '';
                    loadData();
                } else {
                    let error = {};
                    try {
                        error = await res.json();
                    } catch (e) {
                        try {
                            const txt = await res.text();
                            error = { error: txt };
                        } catch(_) { error = { error: 'Failed to block link' }; }
                    }
                    errorDiv.textContent = error.error || 'Failed to block link';
                    errorDiv.style.display = 'block';
                }
            } catch (e) {
                errorDiv.textContent = 'Error blocking link';
                errorDiv.style.display = 'block';
            }
        }

        function displayApproved(submissions) {
            const container = document.getElementById('approvedSubmissions');
            if (submissions.length === 0) {
                container.innerHTML = '<div class="empty-state">✅ ' + adminT('noApproved', adminLanguage) + '</div>';
                return;
            }

            container.innerHTML = '';
            submissions.forEach(sub => {
                const div = document.createElement('div');
                div.className = 'submission approved';
                div.innerHTML =
                    '<strong>👤 User:</strong> ' + escapeForJS(sub.user || 'Anonymous') + '<br>' +
                    '<strong>🔗 Link:</strong> <a href="' + escapeForJS(sub.link) + '" target="_blank" style="color: var(--success);">' + escapeForJS(sub.link) + '</a><br>' +
                    '<strong>✅ Approved:</strong> ' + new Date(sub.id).toLocaleString();
                container.appendChild(div);
            });
        }

        function displayBlocked(blocked) {
            const container = document.getElementById('blockedLinks');
            if (blocked.length === 0) {
                container.innerHTML = '<div class="empty-state">🚫 ' + adminT('noBlocked', adminLanguage) + '</div>';
                return;
            }

            container.innerHTML = '';
            blocked.forEach(link => {
                const div = document.createElement('div');
                div.className = 'submission blocked';
                div.innerHTML =
                    '<div class="submission-header">' +
                        '<div class="submission-info">' +
                            '<strong>🔗 Link:</strong> <a href="' + escapeForJS(link) + '" target="_blank" style="color: var(--danger);">' + escapeForJS(link) + '</a>' +
                        '</div>' +
                        '<div class="submission-actions">' +
                            '<button class="unblock unblock-btn" data-link="' + encodeURIComponent(link) + '">🔓 Unblock</button>' +
                        '</div>' +
                    '</div>';

                // Track info placeholder
                const infoDiv = document.createElement('div');
                infoDiv.className = 'track-info loading';
                infoDiv.textContent = '🎵 Loading track info...';
                div.appendChild(infoDiv);

                container.appendChild(div);

                // Fetch and render track info
                (async () => {
                    const trackInfo = await getTrackInfo(link);
                    if (!trackInfo) {
                        infoDiv.textContent = '❌ Could not load track info';
                        infoDiv.classList.remove('loading');
                        return;
                    }

                    const explicitBadge = trackInfo.explicit ? '<span class="explicit-badge">Explicit</span>' : '';
                    const image = trackInfo.image
                        ? '<img src="' + escapeForJS(trackInfo.image) + '" alt="Album art" class="track-image">'
                        : '<div class="track-image" style="display: flex; align-items: center; justify-content: center; background: var(--surface-light); color: var(--text-muted);">🎵</div>';

                    infoDiv.innerHTML =
                        image +
                        '<div class="track-details">' +
                            '<div class="track-name">🎵 ' + escapeForJS(trackInfo.name) + ' ' + explicitBadge + '</div>' +
                            '<div class="track-artist">👨‍🎤 ' + escapeForJS(trackInfo.artist) + '</div>' +
                            '<div class="track-meta">' +
                                '<span>📀 ' + escapeForJS(trackInfo.album) + '</span>' +
                                '<span>⏱️ ' + formatDuration(trackInfo.duration_ms) + '</span>' +
                                '<span>📊 ' + trackInfo.popularity + '% popularity</span>' +
                            '</div>' +
                        '</div>';

                    infoDiv.classList.remove('loading');
                })();
            });

            document.querySelectorAll('.unblock-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const link = this.getAttribute('data-link');
                    unblockLink(link);
                });
            });
        }

        async function getTrackInfo(link) {
            try {
                const res = await apiCall('/admin/track-info?link=' + encodeURIComponent(link));
                if (res && res.ok) {
                    return await res.json();
                }
            } catch (e) {
                console.error('Error getting track info:', e);
            }
            return null;
        }

        async function approveSubmission(id) {
            if (spotifyAuthRequired) {
                alert('Spotify authentication is required to approve submissions. Please contact Moritz Breier.');
                return;
            }

            try {
                const res = await apiCall('/admin/approve/' + id, { method: 'POST' });
                if (res && res.ok) {
                    loadData();
                } else {
                    const error = await res.json();
                    if (error.error && error.error.includes('refresh token')) {
                        spotifyAuthRequired = true;
                        updateSpotifyWarning();
                        alert('Spotify authentication expired. Please re-authenticate.');
                    } else {
                        alert('Error: ' + error.error);
                    }
                }
            } catch (e) {
                alert('Error approving submission');
            }
        }

        async function unblockLink(encodedLink) {
            const link = decodeURIComponent(encodedLink);
            try {
                const res = await apiCall('/admin/unblock', {
                    method: 'POST',
                    body: JSON.stringify({ link })
                });
                if (res && res.ok) {
                    loadData();
                } else {
                    alert('Error unblocking link');
                }
            } catch (e) {
                alert('Error unblocking link');
            }
        }

        async function searchTracksToBlock() {
            const query = document.getElementById('blockSearchQuery').value.trim();
            const resultsDiv = document.getElementById('blockSearchResults');

            if (!query) {
                resultsDiv.style.display = 'none';
                return;
            }

            try {
                const res = await apiCall('/admin/search-tracks?q=' + encodeURIComponent(query) + '&limit=10');
                if (res && res.ok) {
                    const tracks = await res.json();
                    displayBlockSearchResults(tracks);
                } else {
                    resultsDiv.innerHTML = '<div style="color: var(--danger);">Error searching tracks</div>';
                    resultsDiv.style.display = 'block';
                }
            } catch (e) {
                resultsDiv.innerHTML = '<div style="color: var(--danger);">Network error: ' + e.message + '</div>';
                resultsDiv.style.display = 'block';
            }
        }

        function displayBlockSearchResults(tracks) {
            const resultsDiv = document.getElementById('blockSearchResults');

            if (tracks.length === 0) {
                resultsDiv.innerHTML = '<div style="color: var(--text-muted);">No tracks found</div>';
                resultsDiv.style.display = 'block';
                return;
            }

            let html = '<h4 style="margin: 0 0 1rem 0; color: var(--text);">Search Results (' + tracks.length + ')</h4>';

            tracks.forEach(track => {
                const explicitBadge = track.explicit ? '<span style="background: var(--danger); color: white; font-size: 0.7rem; padding: 0.125rem 0.25rem; border-radius: 0.25rem; margin-left: 0.5rem;">Explicit</span>' : '';
                const image = track.image ?
                    '<img src="' + escapeForJS(track.image) + '" alt="Album art" style="width: 50px; height: 50px; border-radius: 4px; object-fit: cover;">' :
                    '<div style="width: 50px; height: 50px; background: var(--surface-light); border-radius: 4px; display: flex; align-items: center; justify-content: center; color: var(--text-muted);">🎵</div>';

                html += '<div style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: var(--surface); border-radius: 8px; margin-bottom: 0.5rem;">';
                html += image;
                html += '<div style="flex: 1; min-width: 0;">';
                html += '<div style="font-weight: 600; color: var(--text); margin-bottom: 0.25rem;">' + escapeForJS(track.name) + explicitBadge + '</div>';
                html += '<div style="color: var(--text-muted); font-size: 0.9rem;">by ' + escapeForJS(track.artist) + '</div>';
                html += '<div style="color: var(--text-muted); font-size: 0.8rem;">Album: ' + escapeForJS(track.album) + '</div>';
                html += '</div>';
                html += '<button class="block block-from-search" data-url="' + escapeForJS(track.spotify_url) + '">🚫 Block</button>';
                html += '</div>';
            });

            resultsDiv.innerHTML = html;
            // Attach event listeners for block buttons
            resultsDiv.querySelectorAll('.block-from-search').forEach(btn => {
                btn.addEventListener('click', function() {
                    const url = this.getAttribute('data-url');
                    blockTrackFromSearch(url);
                });
            });
            resultsDiv.style.display = 'block';
        }

        async function blockTrackFromSearch(spotifyUrl) {
            try {
                const res = await apiCall('/admin/block', {
                    method: 'POST',
                    body: JSON.stringify({ link: spotifyUrl })
                });

                if (res && res.ok) {
                    const successDiv = document.getElementById('blockLinkSuccess');
                    successDiv.textContent = adminT('trackBlocked', adminLanguage);
                    successDiv.style.display = 'block';

                    // Hide success message after 3 seconds
                    setTimeout(() => {
                        successDiv.style.display = 'none';
                    }, 3000);

                    // Clear search results and query
                    document.getElementById('blockSearchQuery').value = '';
                    document.getElementById('blockSearchResults').style.display = 'none';

                    loadData();
                } else {
                    let error = {};
                    try {
                        error = await res.json();
                    } catch (e) {
                        try {
                            const txt = await res.text();
                            error = { error: txt };
                        } catch(_) { error = { error: 'Unknown error' }; }
                    }
                    const errorDiv = document.getElementById('blockLinkError');
                    errorDiv.textContent = (error && error.error) ? error.error : 'Failed to block track';
                    errorDiv.style.display = 'block';
                }
            } catch (e) {
                const errorDiv = document.getElementById('blockLinkError');
                errorDiv.textContent = 'Network error: ' + e.message;
                errorDiv.style.display = 'block';
            }
        }
    </script>
</body>
</html>
`;

// PUBLIC ROUTES
app.post('/submit', async (req, res) => {
  const { user, link, trackId } = req.body;

  // Support both link and trackId for backwards compatibility
  let finalLink = link;
  if (trackId && !link) {
    finalLink = `https://open.spotify.com/track/${trackId}`;
  }

  if (!finalLink) return res.status(400).send({ error: 'No link or track ID provided' });

  try {
    // Check if track is blocked
    const isBlocked = await isTrackBlocked(finalLink);
    if (isBlocked) return res.status(403).send({ error: 'Link blocked' });

    // Check if song already exists (pending or approved)
    const allSubmissions = await getSubmissions();
    const existingSubmission = allSubmissions.find(s => s.spotify_link === finalLink);
    if (existingSubmission) {
      if (existingSubmission.approved) {
        return res.status(409).send({ error: 'This song has already been approved and added to the playlist' });
      } else {
        return res.status(409).send({ error: 'This song is already pending approval' });
      }
    }

    // Create new submission
    const submissionData = {
      username: user || 'Anonymous',
      spotify_link: finalLink,
      track_id: extractSpotifyTrackId(finalLink),
      approved: false
    };

    await createSubmission(submissionData);
    res.send({ status: 'pending' });
  } catch (error) {
    console.error('Error creating submission:', error);
    res.status(500).send({ error: 'Failed to submit track' });
  }
});

app.get('/pending', async (req, res) => {
  try {
    const pendingSubmissions = await getSubmissions(false);
    // Convert to legacy format for compatibility
    const legacyFormat = pendingSubmissions.map(sub => ({
      id: new Date(sub.created_at).getTime(),
      user: sub.username,
      link: sub.spotify_link,
      approved: sub.approved
    }));
    res.send(legacyFormat);
  } catch (error) {
    console.error('Error getting pending submissions:', error);
    res.status(500).send({ error: 'Failed to get pending submissions' });
  }
});

app.get('/approved', async (req, res) => {
  try {
    const approvedSubmissions = await getSubmissions(true);
    // Convert to legacy format for compatibility
    const legacyFormat = approvedSubmissions.map(sub => ({
      id: new Date(sub.created_at).getTime(),
      user: sub.username,
      link: sub.spotify_link,
      approved: sub.approved
    }));
    res.send(legacyFormat);
  } catch (error) {
    console.error('Error getting approved submissions:', error);
    res.status(500).send({ error: 'Failed to get approved submissions' });
  }
});

app.get('/blocks', async (req, res) => {
  try {
    const blockedTracks = await getBlockedTracks();
    // Convert to legacy format (just array of links)
    const legacyFormat = blockedTracks.map(track => track.spotify_link);
    res.send(legacyFormat);
  } catch (error) {
    console.error('Error getting blocked tracks:', error);
    res.status(500).send({ error: 'Failed to get blocked tracks' });
  }
});

// Public search endpoint for submission form
app.get('/search-tracks', async (req, res) => {
  const { q, limit } = req.query;
  if (!q) return res.status(400).json({ error: 'Search query required' });

  try {
    const tracks = await searchSpotifyTracks(q, parseInt(limit) || 10);
    res.json(tracks);
  } catch (err) {
    if (err.message.includes('refresh token')) res.status(401).json({ error: 'Spotify auth required', authRequired: true });
    else res.status(500).json({ error: err.message });
  }
});

// ADMIN ROUTES
app.get('/admin', (req, res) => {
  res.send(adminPanelHTML);
});

app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = Math.random().toString(36).substring(2) + Date.now().toString(36);
    adminSessions.add(token);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

// Simple test dashboard HTML
const testDashboardHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>beaDJ - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; background: #121212; color: white; }
        .login-form { max-width: 400px; margin: 100px auto; padding: 40px; background: #282828; border-radius: 16px; }
        input { width: 100%; padding: 15px; margin: 10px 0; border: 1px solid #404040; border-radius: 8px; background: #121212; color: white; }
        button { width: 100%; padding: 15px; background: #1db954; color: white; border: none; border-radius: 8px; cursor: pointer; }
        .error { color: #e22134; margin: 10px 0; }
    </style>
</head>
<body>
    <div id="loginForm" class="login-form">
        <h2>🎵 beaDJ Dashboard</h2>
        <input type="text" id="username" placeholder="Username">
        <input type="password" id="password" placeholder="Password" onkeypress="if(event.key==='Enter') login()">
        <button onclick="login()">Login</button>
        <div id="loginError" class="error"></div>
    </div>

    <div id="dashboardPanel" style="display: none;">
        <h1>Welcome to beaDJ Dashboard!</h1>
        <p>Login successful!</p>
        <button onclick="logout()">Logout</button>
    </div>

    <script>
        let sessionToken = localStorage.getItem('dashboardSession');
        let currentUser = null;

        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('loginError');

            console.log('Login attempt:', username);

            if (!username || !password) {
                errorDiv.textContent = 'Please enter username and password';
                return;
            }

            try {
                console.log('Sending login request...');
                const res = await fetch('/dashboard/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                console.log('Response status:', res.status);

                if (res.ok) {
                    const data = await res.json();
                    console.log('Login successful:', data);
                    sessionToken = data.token;
                    currentUser = data.user;
                    localStorage.setItem('dashboardSession', sessionToken);
                    showDashboard();
                } else {
                    const errorData = await res.json().catch(() => ({ error: 'Unknown error' }));
                    console.log('Login failed:', errorData);
                    errorDiv.textContent = errorData.error || 'Invalid credentials';
                }
            } catch (e) {
                console.error('Login error:', e);
                errorDiv.textContent = 'Login failed: ' + e.message;
            }
        }

        function showDashboard() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('dashboardPanel').style.display = 'block';
        }

        function logout() {
            localStorage.removeItem('dashboardSession');
            sessionToken = null;
            currentUser = null;
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('dashboardPanel').style.display = 'none';
        }
    </script>
</body>
</html>
`;

// ----------------------
// DASHBOARD ROUTES (for both admin and regular users)
// ----------------------
app.get('/dashboard', (req, res) => {
  res.send(adminPanelHTML); // full admin panel HTML
});

app.post('/dashboard/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    const user = await authenticateUser(username, password);
    if (user) {
      const token = createSession(user);
      res.json({ token, user: { id: user.id, username: user.username, role: user.role, isAdmin: user.isAdmin } });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/dashboard/verify', requireAuth, (req, res) => res.json({ status: 'authenticated', user: req.user }));
app.get('/dashboard/spotify-status', requireAuth, (req, res) => res.json({ authRequired: isSpotifyAuthNeeded() }));

app.get('/dashboard/pending', requireAuth, async (req, res) => {
  try {
    const pendingSubmissions = await getSubmissions(false);
    const legacyFormat = pendingSubmissions.map(sub => ({
      id: new Date(sub.created_at).getTime(),
      user: sub.username,
      link: sub.spotify_link,
      approved: sub.approved
    }));
    res.json(legacyFormat);
  } catch (error) {
    console.error('Error getting pending submissions:', error);
    res.status(500).json({ error: 'Failed to get pending submissions' });
  }
});

app.get('/dashboard/approved', requireAuth, async (req, res) => {
  try {
    const approvedSubmissions = await getSubmissions(true);
    const legacyFormat = approvedSubmissions.map(sub => ({
      id: new Date(sub.created_at).getTime(),
      user: sub.username,
      link: sub.spotify_link,
      approved: sub.approved
    }));
    res.json(legacyFormat);
  } catch (error) {
    console.error('Error getting approved submissions:', error);
    res.status(500).json({ error: 'Failed to get approved submissions' });
  }
});

app.get('/dashboard/blocked', requireAuth, async (req, res) => {
  try {
    const blockedTracks = await getBlockedTracks();
    const legacyFormat = blockedTracks.map(track => track.spotify_link);
    res.json(legacyFormat);
  } catch (error) {
    console.error('Error getting blocked tracks:', error);
    res.status(500).json({ error: 'Failed to get blocked tracks' });
  }
});

app.get('/dashboard/track-info', requireAuth, async (req, res) => {
  const { link } = req.query;
  const trackId = extractSpotifyTrackId(link);
  if (!trackId) return res.status(400).json({ error: 'Invalid Spotify link' });

  try {
    const trackInfo = await getTrackInfo(trackId);
    if (trackInfo) res.json(trackInfo);
    else res.status(404).json({ error: 'Track info not found' });
  } catch (err) {
    if (err.message.includes('refresh token')) res.status(401).json({ error: 'Spotify auth required', authRequired: true });
    else res.status(500).json({ error: err.message });
  }
});

app.get('/dashboard/search-tracks', requireAuth, async (req, res) => {
  const { q, limit } = req.query;
  if (!q) return res.status(400).json({ error: 'Search query required' });

  try {
    const tracks = await searchSpotifyTracks(q, parseInt(limit) || 10);
    res.json(tracks);
  } catch (err) {
    if (err.message.includes('refresh token')) res.status(401).json({ error: 'Spotify auth required', authRequired: true });
    else res.status(500).json({ error: err.message });
  }
});

// ======================

// USER MANAGEMENT ROUTES - Updated for is_admin

// ======================

app.get('/dashboard/users', requireAdmin, async (req, res) => {

  try {

    const allUsers = await getAllUsers();

    res.json(allUsers.map(u => ({

      id: u.id,

      username: u.username,

      is_admin: u.is_admin,

      role: u.is_admin ? 'admin' : 'user',

      created_at: u.created_at

    })));

  } catch (error) {

    console.error('Error getting users:', error);

    res.status(500).json({ error: 'Failed to get users' });

  }

});

app.post('/dashboard/users', requireAdmin, async (req, res) => {

  const { username, password, isAdmin } = req.body;

  if (!username || !password) {

    return res.status(400).json({ error: 'Username and password required' });

  }

  try {

    // Check if username already exists

    const existingUser = await getUserByUsername(username);

    if (existingUser) {

      return res.status(400).json({ error: 'Username already exists' });

    }

    const newUser = await createUserAccount(

      username, 

      password, 

      isAdmin || false, 

      req.user.username

    );

    

    res.json({

      id: newUser.id,

      username: newUser.username,

      is_admin: newUser.isAdmin,

      role: newUser.role,

      created_at: newUser.created_at

    });

  } catch (err) {

    console.error('Error creating user:', err);

    res.status(500).json({ error: err.message });

  }

});

app.delete('/dashboard/users/:userId', requireAdmin, async (req, res) => {

  try {

    const userToDelete = await supabase

      .from('users')

      .select('*')

      .eq('id', req.params.userId)

      .single();

    if (!userToDelete.data) {

      return res.status(404).json({ error: 'User not found' });

    }

    // Prevent deleting the last admin

    if (userToDelete.data.is_admin) {

      const { data: adminUsers } = await supabase

        .from('users')

        .select('id')

        .eq('is_admin', true);

      

      if (adminUsers && adminUsers.length <= 1) {

        return res.status(400).json({ error: 'Cannot delete the last admin user' });

      }

    }

    // Prevent users from deleting themselves

    if (userToDelete.data.id === req.user.id) {

      return res.status(400).json({ error: 'Cannot delete your own account' });

    }

    await deleteUser(req.params.userId);

    res.json({ status: 'deleted' });

  } catch (error) {

    console.error('Error deleting user:', error);

    res.status(500).json({ error: 'Failed to delete user' });

  }

});

app.patch('/dashboard/users/:userId/admin', requireAdmin, async (req, res) => {

  const { isAdmin } = req.body;

  

  if (typeof isAdmin !== 'boolean') {

    return res.status(400).json({ error: 'isAdmin must be a boolean' });

  }

  try {

    const userToUpdate = await supabase

      .from('users')

      .select('*')

      .eq('id', req.params.userId)

      .single();

    if (!userToUpdate.data) {

      return res.status(404).json({ error: 'User not found' });

    }

    // Prevent removing admin from the last admin

    if (userToUpdate.data.is_admin && !isAdmin) {

      const { data: adminUsers } = await supabase

        .from('users')

        .select('id')

        .eq('is_admin', true);

      

      if (adminUsers && adminUsers.length <= 1) {

        return res.status(400).json({ error: 'Cannot remove admin privileges from the last admin' });

      }

    }

    const updatedUser = await updateUserAdminStatus(req.params.userId, isAdmin);

    res.json({

      id: updatedUser.id,

      username: updatedUser.username,

      is_admin: updatedUser.is_admin,

      role: updatedUser.is_admin ? 'admin' : 'user'

    });

  } catch (error) {

    console.error('Error updating user admin status:', error);

    res.status(500).json({ error: 'Failed to update user' });

  }

});

// Mirror routes for /admin prefix

app.get('/admin/users', requireAdmin, async (req, res) => {

  try {

    const allUsers = await getAllUsers();

    res.json(allUsers.map(u => ({

      id: u.id,

      username: u.username,

      is_admin: u.is_admin,

      role: u.is_admin ? 'admin' : 'user',

      created_at: u.created_at

    })));

  } catch (error) {

    console.error('Error getting users:', error);

    res.status(500).json({ error: 'Failed to get users' });

  }

});

// ----------------------
// ADMIN GET ROUTES (mirror dashboard)
// ----------------------
app.get('/admin/verify', requireAuth, (req, res) => res.json({ status: 'authenticated', user: req.user }));
app.get('/admin/spotify-status', requireAuth, (req, res) => res.json({ authRequired: isSpotifyAuthNeeded() }));
app.get('/admin/pending', requireAuth, async (req, res) => {
  try {
    const pendingSubmissions = await getSubmissions(false);
    const legacyFormat = pendingSubmissions.map(sub => ({
      id: new Date(sub.created_at).getTime(),
      user: sub.username,
      link: sub.spotify_link,
      approved: sub.approved
    }));
    res.json(legacyFormat);
  } catch (error) {
    console.error('Error getting pending submissions:', error);
    res.status(500).json({ error: 'Failed to get pending submissions' });
  }
});

app.get('/admin/approved', requireAuth, async (req, res) => {
  try {
    const approvedSubmissions = await getSubmissions(true);
    const legacyFormat = approvedSubmissions.map(sub => ({
      id: new Date(sub.created_at).getTime(),
      user: sub.username,
      link: sub.spotify_link,
      approved: sub.approved
    }));
    res.json(legacyFormat);
  } catch (error) {
    console.error('Error getting approved submissions:', error);
    res.status(500).json({ error: 'Failed to get approved submissions' });
  }
});

app.get('/admin/blocked', requireAuth, async (req, res) => {
  try {
    const blockedTracks = await getBlockedTracks();
    const legacyFormat = blockedTracks.map(track => track.spotify_link);
    res.json(legacyFormat);
  } catch (error) {
    console.error('Error getting blocked tracks:', error);
    res.status(500).json({ error: 'Failed to get blocked tracks' });
  }
});

app.get('/admin/track-info', requireAuth, async (req, res) => {
  const { link } = req.query;
  const trackId = extractSpotifyTrackId(link);
  if (!trackId) return res.status(400).json({ error: 'Invalid Spotify link' });

  try {
    const trackInfo = await getTrackInfo(trackId);
    if (trackInfo) res.json(trackInfo);
    else res.status(404).json({ error: 'Track info not found' });
  } catch (err) {
    if (err.message.includes('refresh token')) res.status(401).json({ error: 'Spotify auth required', authRequired: true });
    else res.status(500).json({ error: err.message });
  }
});

app.get('/admin/search-tracks', requireAuth, async (req, res) => {
  const { q, limit } = req.query;
  if (!q) return res.status(400).json({ error: 'Search query required' });

  try {
    const tracks = await searchSpotifyTracks(q, parseInt(limit) || 10);
    res.json(tracks);
  } catch (err) {
    if (err.message.includes('refresh token')) res.status(401).json({ error: 'Spotify auth required', authRequired: true });
    else res.status(500).json({ error: err.message });
  }
});

// ======================

// ADMIN POST ROUTES - Updated approve to track approved_by

// ======================

app.post('/admin/approve/:id', requireAuth, async (req, res) => {

  try {

    // Find submission by timestamp ID (legacy format)

    const allSubmissions = await getSubmissions();

    const sub = allSubmissions.find(s => new Date(s.created_at).getTime() == req.params.id);

    if (!sub) {

      return res.status(404).json({ error: 'Submission not found' });

    }

    if (isSpotifyAuthNeeded()) {

      return res.status(401).json({ error: 'Spotify authentication required', authRequired: true });

    }

    const trackId = extractSpotifyTrackId(sub.spotify_link);

    if (!trackId) {

      return res.status(400).json({ error: 'Invalid Spotify link' });

    }

    await addTrackToSpotifyPlaylist(trackId);

    // Update submission in database with approved_by

    await updateSubmission(sub.id, {

      approved: true,

      approved_at: new Date().toISOString(),

      approved_by: req.user.id // Track who approved it

    });

    console.log(`Track approved by ${req.user.username}: ${sub.spotify_link}`);

    res.json({ 

      status: 'approved', 

      id: new Date(sub.created_at).getTime(),

      approved_by: req.user.username

    });

  } catch (err) {

    console.error('Error approving submission:', err);

    if (err.message.includes('refresh token') || err.message.includes('Spotify')) {

      res.status(401).json({

        error: 'Spotify authentication required. Please re-authenticate.',

        authRequired: true

      });

    } else {

      res.status(500).json({

        error: 'Failed to approve submission: ' + err.message

      });

    }

  }

});

app.post('/admin/block', requireAuth, async (req, res) => {
  const { link } = req.body;
  if (!link) return res.status(400).json({ error: 'No link provided' });

  try {
    // Check if already blocked
    const alreadyBlocked = await isTrackBlocked(link);
    if (!alreadyBlocked) {
      const trackData = {
        spotify_link: link,
        track_id: extractSpotifyTrackId(link),
        blocked_by: req.user?.id || null
      };
      await createBlockedTrack(trackData);
    }

    // Remove from submissions if exists
    const allSubmissions = await getSubmissions();
    const submissionToDelete = allSubmissions.find(s => s.spotify_link === link);
    if (submissionToDelete) {
      await deleteSubmission(submissionToDelete.id);
    }

    res.json({ status: 'blocked', link });
  } catch (error) {
    console.error('Error blocking track:', error);
    res.status(500).json({ error: 'Failed to block track' });
  }
});

app.post('/admin/unblock', requireAuth, async (req, res) => {
  const { link } = req.body;
  if (!link) return res.status(400).json({ error: 'No link provided' });

  try {
    await deleteBlockedTrack(link);
    res.json({ status: 'unblocked', link });
  } catch (error) {
    console.error('Error unblocking track:', error);
    res.status(500).json({ error: 'Failed to unblock track' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: {
      hasSpotifyConfig: !!(CLIENT_ID && CLIENT_SECRET && PLAYLIST_ID),
      hasSupabaseConfig: !!(SUPABASE_URL && SUPABASE_ANON_KEY),
      port: PORT
    }
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🎵 beaDJ server running on port ${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/dashboard`);
  console.log(`🔐 Admin user: admin`);
  console.log(`🔐 Admin password: ${ADMIN_PASSWORD}`);
  console.log(`🎵 Spotify auth password: ${SPOTIFY_AUTH_PASSWORD}`);
  console.log(`🎵 Spotify auth page: http://localhost:${PORT}/spotify-auth`);

  if (isSpotifyAuthNeeded()) {
    console.log('⚠️  Spotify authentication required - visit /spotify-auth to authenticate');
  } else {
    console.log('✅ Spotify tokens loaded successfully');
  }
});
