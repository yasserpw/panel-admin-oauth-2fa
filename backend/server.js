// ============================================
// BACKEND - OAUTH 2.0 SIMPLE (PRODUCCIÓN)
// Desplegado en RENDER
// ============================================

const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();

// ✅ CORS Configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Configuración - Soporta localhost y producción
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5000';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USER_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';

// ✅ RUTA CRÍTICA: /auth/google (obtiene la URL de Google)
app.get('/auth/google', (req, res) => {
  const authUrl = GOOGLE_AUTH_URL + '?' + querystring.stringify({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${BACKEND_URL}/auth/google/callback`,
    response_type: 'code',
    scope: 'profile email',
    access_type: 'offline',
    prompt: 'consent'
  });

  res.json({ authUrl });
});

// ✅ RUTA: /auth/google/callback (recibe el código de Google)
app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.status(400).json({ error: 'No authorization code received' });
  }

  try {
    // Intercambiar código por token
    const tokenResponse = await axios.post(GOOGLE_TOKEN_URL, {
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      code,
      redirect_uri: `${BACKEND_URL}/auth/google/callback`,
      grant_type: 'authorization_code'
    });

    const { access_token } = tokenResponse.data;

    // Obtener información del usuario
    const userResponse = await axios.get(GOOGLE_USER_URL, {
      headers: { Authorization: `Bearer ${access_token}` }
    });

    const userData = userResponse.data;

    // Guardar token en cookie
    res.cookie('access_token', access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    // Redirigir al dashboard con userData
    const dashboardUrl = `${FRONTEND_URL}/dashboard.html?user=${encodeURIComponent(JSON.stringify(userData))}`;
    res.redirect(dashboardUrl);

  } catch (error) {
    console.error('Error during OAuth callback:', error.message);
    res.status(500).json({ error: 'Authentication failed', details: error.message });
  }
});

// ✅ RUTA: /profile (obtener perfil del usuario)
app.get('/profile', (req, res) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  res.json({ message: 'User is authenticated', token });
});

// ✅ RUTA: /logout
app.post('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.json({ message: 'Logged out successfully' });
});

// Health check
app.get('/', (req, res) => {
  res.json({ message: 'Backend running', environment: process.env.NODE_ENV });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Puerto
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n${'='.repeat(40)}`);
  console.log('✅ Backend ejecutándose en puerto', PORT);
  console.log(`Frontend URL: ${FRONTEND_URL}`);
  console.log(`Backend URL: ${BACKEND_URL}`);
  console.log(`Redirect URI: ${BACKEND_URL}/auth/google/callback`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
  console.log(`${'='.repeat(40)}\n`);
});
