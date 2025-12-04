const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const axios = require('axios');

const app = express();
const PORT = 3000;

// Discord Configuration
const DISCORD_CLIENT_ID = '1156938411773546587';
const DISCORD_CLIENT_SECRET = 'hdZVbwz1rPVjkjlHbEi2EriiK-ntnRHN';
const DISCORD_REDIRECT_URI = 'http://localhost:3000/api/auth/discord/callback';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); // Serve frontend files

// Database Setup
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        createTables();
    }
});

function createTables() {
    db.serialize(() => {
        // Licenses Table
        db.run(`CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            ip TEXT,
            discord_id TEXT,
            status TEXT DEFAULT 'active',
            expires_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            // Migration: Add expires_at if it doesn't exist (for existing dbs)
            if (!err) {
                db.run(`ALTER TABLE licenses ADD COLUMN expires_at DATETIME`, (err) => { });
                db.run(`ALTER TABLE licenses ADD COLUMN discord_id TEXT`, (err) => { });
            }
        });

        // Logs Table
        db.run(`CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            ip TEXT,
            resource_name TEXT,
            server_name TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Admin Users Table (for dashboard login)
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )`);

        // Discord Admin Users Table
        db.run(`CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Insert default admin user if not exists (admin:admin) - In production use hashed passwords!
        db.run(`INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin')`);
    });
}

// API Endpoints

// Verify License
app.get('/api/verify/:license_key', (req, res) => {
    const licenseKey = req.params.license_key;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    db.get(`SELECT * FROM licenses WHERE key = ?`, [licenseKey], (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Internal Server Error");
        }

        if (!row) {
            logRequest(licenseKey, clientIp, "Unknown", "Unknown", "Invalid License");
            return res.send("Sorry, this license does not exist.");
        }

        if (row.status !== 'active') {
            logRequest(licenseKey, clientIp, "Unknown", "Unknown", "Inactive License");
            return res.send("Sorry, your license is not active.");
        }

        // Expiration Check
        if (row.expires_at) {
            const now = new Date();
            const expires = new Date(row.expires_at);
            if (now > expires) {
                logRequest(licenseKey, clientIp, "Unknown", "Unknown", "Expired License");
                return res.send("Sorry, your license has expired.");
            }
        }

        // IP Check
        if (row.ip && row.ip !== clientIp) {
            logRequest(licenseKey, clientIp, "Unknown", "Unknown", "Invalid IP");
            return res.send("Sorry, this license is bound to another IP.");
        }

        // Bind IP if null
        if (!row.ip) {
            db.run(`UPDATE licenses SET ip = ? WHERE id = ?`, [clientIp, row.id]);
        }

        logRequest(licenseKey, clientIp, "Unknown", "Unknown", "Success");
        res.send("License Verified Successfully.");
    });
});

// Helper to log requests
function logRequest(key, ip, resource, server, status) {
    db.run(`INSERT INTO logs (license_key, ip, resource_name, server_name, status) VALUES (?, ?, ?, ?, ?)`,
        [key, ip, resource, server, status], (err) => {
            if (err) console.error("Error logging:", err.message);
        });
}

// Admin API

// Login (Legacy Username/Password)
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) {
            res.json({ success: true, token: 'dummy-token' }); // In production use JWT
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    });
});

// Discord Auth Endpoints
app.get('/api/auth/discord/redirect', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&response_type=code&scope=identify`;
    res.redirect(url);
});

app.get('/api/auth/discord/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send('No code provided');

    try {
        const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: DISCORD_CLIENT_SECRET,
            code,
            grant_type: 'authorization_code',
            redirect_uri: DISCORD_REDIRECT_URI,
            scope: 'identify',
        }).toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const userRes = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenRes.data.access_token}` }
        });

        const discordId = userRes.data.id;
        const username = userRes.data.username;

        // Check if this is the first admin (System Setup)
        db.get('SELECT count(*) as count FROM admin_users', [], (err, countRow) => {
            if (err) return res.status(500).send('Database error checking admins');

            if (countRow.count === 0) {
                // First user becomes admin
                db.run('INSERT INTO admin_users (discord_id, username) VALUES (?, ?)', [discordId, username], (err) => {
                    if (err) return res.status(500).send('Error creating first admin');
                    // Redirect to dashboard
                    res.redirect(`/dashboard.html?token=admin_token_${discordId}&username=${username}`);
                });
            } else {
                // Normal check
                db.get('SELECT * FROM admin_users WHERE discord_id = ?', [discordId], (err, row) => {
                    if (err) return res.status(500).send('Database error');
                    if (!row) return res.status(403).send(`Access Denied: You are not an authorized admin. Your ID: ${discordId}`);

                    // Success
                    res.redirect(`/dashboard.html?token=admin_token_${discordId}&username=${username}`);
                });
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).send('Authentication failed');
    }
});

// Admin Management Endpoints
app.get('/api/admin/admins', (req, res) => {
    db.all('SELECT * FROM admin_users', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/admin/admins', (req, res) => {
    const { discord_id, username } = req.body;
    db.run('INSERT INTO admin_users (discord_id, username) VALUES (?, ?)', [discord_id, username], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, discord_id, username });
    });
});

app.delete('/api/admin/admins/:id', (req, res) => {
    db.run('DELETE FROM admin_users WHERE id = ?', [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});


// Get Stats
app.get('/api/admin/stats', (req, res) => {
    db.serialize(() => {
        db.get("SELECT COUNT(*) as count FROM licenses", (err, licenses) => {
            db.get("SELECT COUNT(*) as count FROM licenses WHERE status = 'active'", (err, active) => {
                db.get("SELECT COUNT(*) as count FROM logs", (err, logs) => {
                    res.json({
                        total_licenses: licenses.count,
                        active_licenses: active.count,
                        total_logs: logs.count
                    });
                });
            });
        });
    });
});

// List Licenses
app.get('/api/admin/licenses', (req, res) => {
    db.all("SELECT * FROM licenses ORDER BY created_at DESC", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Create License
app.post('/api/admin/licenses', (req, res) => {
    const { key, expires_at, discord_id } = req.body;
    // Generate a random 10-digit number if no key provided
    const finalKey = key || Math.floor(1000000000 + Math.random() * 9000000000).toString();
    db.run(`INSERT INTO licenses (key, expires_at, discord_id) VALUES (?, ?, ?)`, [finalKey, expires_at || null, discord_id || null], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, key: finalKey, expires_at, discord_id });
    });
});

// Update License (IP, Expiration, Discord ID)
app.put('/api/admin/licenses/:id', (req, res) => {
    const { ip, expires_at, discord_id } = req.body;
    // Handle empty strings as null
    const finalIp = ip === '' ? null : ip;
    const finalExpires = expires_at === '' ? null : expires_at;
    const finalDiscordId = discord_id === '' ? null : discord_id;

    db.run(`UPDATE licenses SET ip = ?, expires_at = ?, discord_id = ? WHERE id = ?`, [finalIp, finalExpires, finalDiscordId, req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Delete License
app.delete('/api/admin/licenses/:id', (req, res) => {
    db.run(`DELETE FROM licenses WHERE id = ?`, [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Reset IP (Legacy endpoint, can use PUT now but keeping for compatibility if needed)
app.post('/api/admin/licenses/:id/reset-ip', (req, res) => {
    db.run(`UPDATE licenses SET ip = NULL WHERE id = ?`, [req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Toggle Status (Ban/Unban)
app.post('/api/admin/licenses/:id/toggle', (req, res) => {
    db.get(`SELECT status FROM licenses WHERE id = ?`, [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'Not found' });
        const newStatus = row.status === 'active' ? 'banned' : 'active';
        db.run(`UPDATE licenses SET status = ? WHERE id = ?`, [newStatus, req.params.id], function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, status: newStatus });
        });
    });
});

// Get Logs
app.get('/api/admin/logs', (req, res) => {
    db.all("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Client API

// Client Reset IP
app.post('/api/client/reset-ip', (req, res) => {
    const { license_key, discord_id } = req.body;

    if (!license_key || !discord_id) {
        return res.status(400).json({ success: false, message: 'Missing license key or Discord ID' });
    }

    db.get(`SELECT * FROM licenses WHERE key = ?`, [license_key], (err, row) => {
        if (err) return res.status(500).json({ success: false, message: 'Database error' });
        if (!row) return res.status(404).json({ success: false, message: 'License not found' });

        if (row.discord_id !== discord_id) {
            return res.status(403).json({ success: false, message: 'Invalid Discord ID for this license' });
        }

        db.run(`UPDATE licenses SET ip = NULL WHERE id = ?`, [row.id], (err) => {
            if (err) return res.status(500).json({ success: false, message: 'Failed to reset IP' });
            res.json({ success: true, message: 'IP Address reset successfully' });
        });
    });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
