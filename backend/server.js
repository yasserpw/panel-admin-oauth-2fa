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

const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());

// Configuración - Soporta localhost y producción
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:5000';
const REDIRECT_URI = `${BACKEND_URL}/auth/google/callback`;
const NODE_ENV = process.env.NODE_ENV || 'development';

console.log(`🌍 Environment: ${NODE_ENV}`);
console.log(`🎯 Frontend URL: ${FRONTEND_URL}`);
console.log(`🎯 Backend URL: ${BACKEND_URL}`);
console.log(`🎯 Redirect URI: ${REDIRECT_URI}`);

// Almacenamiento global
const users = new Map();
const oauthStates = new Map();

// Middleware
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ============================================
// RUTAS OAUTH
// ============================================

// 1. Iniciar login
app.get('/api/auth/login', (req, res) => {
  const state = Math.random().toString(36).substring(7);
  oauthStates.set(state, Date.now());

  const params = querystring.stringify({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state: state,
    access_type: 'offline'
  });

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  res.json({ authUrl });
});

// 2. Callback de Google
app.get('/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!oauthStates.has(state)) {
    return res.status(400).send('Estado inválido');
  }

  oauthStates.delete(state);

  if (!code) {
    return res.status(400).send('Código no recibido');
  }

  try {
    // Intercambiar código por token
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      code: code,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code'
    });

    const accessToken = tokenResponse.data.access_token;
    const refreshToken = tokenResponse.data.refresh_token;

    // Obtener info del usuario
    const userResponse = await axios.get(
      'https://openidconnect.googleapis.com/v1/userinfo',
      { headers: { 'Authorization': `Bearer ${accessToken}` } }
    );

    const googleUser = userResponse.data;
    const userId = googleUser.sub;

    // Guardar usuario
    if (!users.has(userId)) {
      users.set(userId, {
        id: userId,
        email: googleUser.email,
        name: googleUser.name,
        picture: googleUser.picture,
        createdAt: new Date()
      });
    }

    // ✅ GUARDAR TOKEN EN COOKIE - Esto es lo IMPORTANTE para producción
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',  // HTTPS en producción
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 3600000,  // 1 hora
      domain: NODE_ENV === 'production' ? undefined : 'localhost'
    });

    res.cookie('userId', userId, {
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,  // 24 horas
      domain: NODE_ENV === 'production' ? undefined : 'localhost'
    });

    // ✅ GUARDAR TOKEN EN SESIÓN TAMBIÉN
    res.cookie('sessionToken', JSON.stringify({
      userId: userId,
      accessToken: accessToken,
      createdAt: new Date().toISOString()
    }), {
      httpOnly: false,  // Accessible desde JS si es necesario
      secure: NODE_ENV === 'production',
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000
    });

    // Redirigir al dashboard
    const redirectUrl = `${FRONTEND_URL}/dashboard?token=${accessToken}&userId=${userId}`;
    console.log(`✅ Usuario autenticado: ${googleUser.email}`);
    res.redirect(redirectUrl);

  } catch (error) {
    console.error('❌ Error OAuth:', error.message);
    res.redirect(`${FRONTEND_URL}/?error=auth_failed`);
  }
});

// ============================================
// RUTAS PROTEGIDAS
// ============================================

// Verificar sesión
app.get('/api/auth/me', (req, res) => {
  const userId = req.cookies.userId;
  
  if (!userId || !users.has(userId)) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const user = users.get(userId);
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    picture: user.picture,
    authenticated: true
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('accessToken');
  res.clearCookie('userId');
  res.clearCookie('sessionToken');
  res.json({ message: 'Sesión cerrada' });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK',
    environment: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// ============================================
// RUTAS DE PRUEBA
// ============================================

app.get('/api/users', (req, res) => {
  const usersList = Array.from(users.values()).map(u => ({
    id: u.id,
    email: u.email,
    name: u.name,
    createdAt: u.createdAt
  }));
  res.json(usersList);
});

// ============================================
// INICIAR SERVIDOR
// ============================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n✅ ========================================`);
  console.log(`🚀 Backend ejecutándose en puerto ${PORT}`);
  console.log(`✅ ========================================\n`);
});