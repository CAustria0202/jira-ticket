const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const FormData = require('form-data');

const app = express();
const PORT = process.env.PORT || 3001;

require('dotenv').config();
const userSessions = new Map(); // cloudId => access_token

const authBase = "https://auth.atlassian.com";
const apiBase = "https://api.atlassian.com";

app.get('/auth/login', (req, res) => {
    const authUrl = `${authBase}/authorize?audience=api.atlassian.com&client_id=${process.env.ATLASSIAN_CLIENT_ID}&scope=read%3Ajira-user%20read%3Ajira-work%20write%3Ajira-work&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}&response_type=code&prompt=consent`;
    res.redirect(authUrl);
});

app.get('/oauth/callback', async (req, res) => {
    const code = req.query.code;

    try {
        const tokenRes = await axios.post(`${authBase}/oauth/token`, {
            grant_type: 'authorization_code',
            client_id: process.env.ATLASSIAN_CLIENT_ID,
            client_secret: process.env.ATLASSIAN_CLIENT_SECRET,
            code,
            redirect_uri: process.env.REDIRECT_URI
        });

        const access_token = tokenRes.data.access_token;

        const resourceRes = await axios.get(`${apiBase}/oauth/token/accessible-resources`, {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        const cloudId = resourceRes.data[0].id;
        userSessions.set(cloudId, access_token);

        console.log(`OAuth successful for cloudId: ${cloudId}`);
        res.redirect(`/?cloudId=${cloudId}`);
    } catch (err) {
        console.error("OAuth failed:", err.response?.data || err.message);
        res.status(500).send("OAuth flow failed.");
    }
});

// Configure multer for file uploads
const upload = multer({
    dest: 'uploads/',
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
        files: 10 // Maximum 10 files
    },
    fileFilter: (req, file, cb) => {
        console.log(`File upload: ${file.originalname} (${file.mimetype})`);
        cb(null, true);
    }
});

// Middleware
app.use(cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Cloud-Id', 'Accept']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Cleanup function for uploaded files
function cleanupFile(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            console.log(`Cleaned up temporary file: ${filePath}`);
        }
    } catch (error) {
        console.error(`Error cleaning up file ${filePath}:`, error.message);
    }
}

// Enhanced attachment upload endpoint
app.post('/api/jira/issue/:issueKey/attachments', upload.array('file'), async (req, res) => {
    const { issueKey } = req.params;
    const cloudId = req.query.cloudId || req.headers['x-cloud-id'];
    const token = userSessions.get(cloudId);
    const uploadedFiles = req.files;

    console.log(`Attachment upload request for issue ${issueKey}, cloudId: ${cloudId}`);

    if (!cloudId || !token) {
        return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }

    if (!uploadedFiles || uploadedFiles.length === 0) {
        return res.status(400).json({ error: 'No files uploaded' });
    }

    try {
        const fullUrl = `${apiBase}/ex/jira/${cloudId}/rest/api/3/issue/${issueKey}/attachments`;

        const formData = new FormData();
        uploadedFiles.forEach(file => {
            formData.append('file', fs.createReadStream(file.path), file.originalname);
        });

        const response = await axios.post(fullUrl, formData, {
            headers: {
                Authorization: `Bearer ${token}`,
                'X-Atlassian-Token': 'no-check',
                ...formData.getHeaders()
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        uploadedFiles.forEach(file => cleanupFile(file.path));
        res.json({ success: true, attachments: response.data });

    } catch (error) {
        console.error('Attachment upload error:', error.response?.data || error.message);
        uploadedFiles.forEach(file => cleanupFile(file.path));
        res.status(error.response?.status || 500).json({ 
            error: error.response?.data?.errorMessages?.[0] || error.message 
        });
    }
});

// Enhanced proxy for all other JIRA API requests
app.use('/api/jira', async (req, res) => {
    try {
        const cloudId = req.query.cloudId || req.headers['x-cloud-id'];
        const token = userSessions.get(cloudId);

        console.log(`JIRA API Request: ${req.method} ${req.path}, cloudId: ${cloudId}, hasToken: ${!!token}`);

        if (!cloudId || !token) {
            return res.status(401).json({ error: 'User not authenticated. Please sign in with JIRA.' });
        }

        const jiraEndpoint = req.path;
        const fullUrl = `${apiBase}/ex/jira/${cloudId}/rest/api/3${jiraEndpoint}`;

        // Filter out cloudId from query params to avoid sending it to JIRA
        const filteredQuery = { ...req.query };
        delete filteredQuery.cloudId;

        const axiosConfig = {
            method: req.method,
            url: fullUrl,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            params: filteredQuery,
            timeout: 30000
        };

        if (req.method !== 'GET' && req.body) {
            axiosConfig.data = req.body;
        }

        console.log(`Making request to: ${fullUrl}`);
        const response = await axios(axiosConfig);
        
        console.log(`JIRA API Response: ${response.status} for ${req.method} ${req.path}`);
        res.status(response.status).json(response.data);
        
    } catch (error) {
        console.error(`JIRA API Error for ${req.method} ${req.path}:`, error.response?.data || error.message);
        
        const status = error.response?.status || 500;
        const errorMessage = error.response?.data?.errorMessages?.[0] || 
                           error.response?.data?.message || 
                           error.message;
        
        res.status(status).json({ error: errorMessage });
    }
});

// Debug endpoint to check active sessions
app.get('/api/debug/sessions', (req, res) => {
    const sessions = Array.from(userSessions.keys()).map(cloudId => ({
        cloudId,
        hasToken: userSessions.has(cloudId)
    }));
    res.json({ sessions });
});

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                error: 'File too large',
                message: 'File size exceeds 10MB limit'
            });
        } else if (error.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({
                error: 'Too many files',
                message: 'Maximum 10 files allowed'
            });
        }
    }
    
    res.status(500).json({
        error: 'Internal server error',
        message: error.message
    });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Received SIGTERM, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('Received SIGINT, shutting down gracefully');
    process.exit(0);
});

app.listen(PORT, () => {
    console.log('Enhanced JIRA Proxy Server starting...');
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Place your HTML file in the 'public' folder as 'index.html'`);
    console.log(`API endpoints available:`);
    console.log(`   GET  /auth/login - Start OAuth flow`);
    console.log(`   GET  /oauth/callback - OAuth callback`);
    console.log(`   GET  /api/debug/sessions - Debug active sessions`);
    console.log(`   All  /api/jira/* - Proxy to JIRA API`);
    console.log('Server ready to handle requests');
});