// server.js - Enhanced Production-Ready Backend
import express from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import bodyParser from 'body-parser';
import { createServer } from 'http';
import { Server } from 'socket.io';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import fetch from 'node-fetch';
import compression from 'compression';
import { admin, db, FieldValue } from './firebaseAdmin.js';
import notificationService from './services/notificationService.js'; // ✅ Fixed import
import * as client from 'prom-client';
import { Expo } from 'expo-server-sdk';

// Load environment variables
dotenv.config();

// ✅ Enhanced Configuration
const app = express();
const server = createServer(app);

// ✅ Production Configuration
const HOST = process.env.RENDER_INTERNAL_HOST || '0.0.0.0';
const PORT = process.env.PORT || 10000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const MAX_CONNECTIONS = parseInt(process.env.MAX_CONNECTIONS) || 1000;
const ENABLE_METRICS = process.env.ENABLE_METRICS !== 'false';

// ✅ External URL helper
const getExternalUrl = () => {
  if (process.env.RENDER_EXTERNAL_URL) {
    return process.env.RENDER_EXTERNAL_URL;
  }
  if (process.env.EXTERNAL_URL) {
    return process.env.EXTERNAL_URL;
  }
  return `http://localhost:${PORT}`;
};

// ✅ Enhanced Prometheus Metrics Setup
// ✅ ENHANCED: Safe Prometheus Metrics Setup
const register = new client.Registry();
let httpRequestDurationMicroseconds, httpRequestTotal, activeWebSocketConnections;
let totalMessages, notificationsSent, authenticationAttempts, firebaseOperations;
let connectionErrors, resourceUsage;

if (ENABLE_METRICS) {
  // Collect default Node.js metrics
  client.collectDefaultMetrics({ 
    register,
    timeout: 10000,
    gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
    eventLoopMonitoringPrecision: 10,
  });

  // Custom metrics
  httpRequestDurationMicroseconds = new client.Histogram({
    name: 'http_request_duration_ms',
    help: 'Duration of HTTP requests in ms',
    labelNames: ['method', 'route', 'status_code', 'user_agent'],
    buckets: [0.1, 5, 15, 50, 100, 200, 300, 400, 500, 1000, 2000, 5000]
  });

  httpRequestTotal = new client.Counter({
    name: 'http_requests_total',
    help: 'Total number of HTTP requests',
    labelNames: ['method', 'route', 'status_code', 'user_agent']
  });

  activeWebSocketConnections = new client.Gauge({
    name: 'websocket_connections_active',
    help: 'Number of active WebSocket connections'
  });

  totalMessages = new client.Counter({
    name: 'chat_messages_total',
    help: 'Total number of chat messages sent',
    labelNames: ['message_type', 'status', 'sender_platform']
  });

  notificationsSent = new client.Counter({
    name: 'notifications_sent_total',
    help: 'Total number of push notifications sent',
    labelNames: ['platform', 'status', 'notification_type']
  });

  authenticationAttempts = new client.Counter({
    name: 'authentication_attempts_total',
    help: 'Total number of authentication attempts',
    labelNames: ['method', 'status', 'failure_reason']
  });

  firebaseOperations = new client.Counter({
    name: 'firebase_operations_total',
    help: 'Total number of Firebase operations',
    labelNames: ['operation_type', 'status', 'collection']
  });

  connectionErrors = new client.Counter({
    name: 'connection_errors_total',
    help: 'Total number of connection errors',
    labelNames: ['error_type', 'source']
  });

  resourceUsage = new client.Gauge({
    name: 'resource_usage',
    help: 'System resource usage',
    labelNames: ['resource_type']
  });

  // Register metrics
  [httpRequestDurationMicroseconds, httpRequestTotal, activeWebSocketConnections, 
   totalMessages, notificationsSent, authenticationAttempts, firebaseOperations, 
   connectionErrors, resourceUsage].forEach(metric => register.registerMetric(metric));

  console.log('✅ Prometheus metrics enabled');
} else {
  console.log('⚠️ Prometheus metrics disabled');
}
// ✅ Safe metrics helper
function safeIncrementMetric(metric, labels = []) {
  if (ENABLE_METRICS && metric && typeof metric.inc === 'function') {
    try {
      if (labels.length > 0) {
        metric.labels(...labels).inc();
      } else {
        metric.inc();
      }
    } catch (error) {
      console.warn('⚠️ Metrics error:', error.message);
    }
  }
}


// ✅ Enhanced Socket.io Configuration
const io = new Server(server, {
  cors: {
    origin: IS_PRODUCTION ? process.env.ALLOWED_ORIGINS?.split(',') || "*" : "*",
    methods: ["GET", "POST"],
    credentials: false
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e6, // 1MB
  allowEIO3: true,
  connectTimeout: 45000,
  upgradeTimeout: 30000
});

// ✅ Enhanced Security Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: IS_PRODUCTION ? {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "https:"],
    }
  } : false,
  hsts: IS_PRODUCTION ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false
}));

// ✅ Enhanced CORS Configuration
app.use(cors({
  origin: IS_PRODUCTION ? (origin, callback) => {
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['*'];
    if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  } : "*",
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key', 'User-Agent'],
  maxAge: 86400 // 24 hours
}));

// ✅ Compression and Body Parsing
app.use(compression());
app.use(bodyParser.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
// ✅ Add root route handler
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'SecureLink Server is running',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// ✅ Handle HEAD requests for health checks
app.head('/', (req, res) => {
  res.status(200).end();
});

// ✅ Enhanced Request Logging and Metrics
// ✅ FIXED: Add conditional check for metrics
app.use((req, res, next) => {
  const start = Date.now();
  const userAgent = req.get('User-Agent') || 'unknown';
  
  res.on('finish', () => {
    const responseTimeInMs = Date.now() - start;
    const route = req.route?.path || req.path;
    
    // ✅ Only use metrics if they're enabled and defined
    if (ENABLE_METRICS && typeof httpRequestDurationMicroseconds !== 'undefined') {
      httpRequestDurationMicroseconds
        .labels(req.method, route, res.statusCode.toString(), userAgent.split('/')[0])
        .observe(responseTimeInMs);
      
      httpRequestTotal
        .labels(req.method, route, res.statusCode.toString(), userAgent.split('/')[0])
        .inc();
    }
    
    // Log slow requests
    if (responseTimeInMs > 1000) {
      console.warn(`🐌 Slow request: ${req.method} ${req.path} took ${responseTimeInMs}ms`);
    }
  });
  
  next();
});


// ✅ Enhanced Rate Limiting with IP whitelist
// ✅ FIXED: Rate limiting with conditional metrics
const createRateLimiter = (windowMs, max, message, skipWhitelist = []) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message, code: 'RATE_LIMITED' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      const clientIp = req.ip || req.connection.remoteAddress;
      return skipWhitelist.some(ip => clientIp.includes(ip));
    },
    handler: (req, res) => {
      console.warn(`⚠️ Rate limit exceeded for IP: ${req.ip}, path: ${req.path}`);
      
      // ✅ Only increment counter if metrics are enabled and defined
      if (ENABLE_METRICS && typeof connectionErrors !== 'undefined') {
        connectionErrors.labels('rate_limit', 'http').inc();
      }
      
      res.status(429).json({ 
        error: message, 
        code: 'RATE_LIMITED', 
        retryAfter: Math.ceil(windowMs / 1000) 
      });
    },
    keyGenerator: (req) => {
      return req.ip + ':' + req.path;
    }
  });
};


// Apply rate limiting
const whitelistedIPs = process.env.WHITELISTED_IPS?.split(',') || [];
app.use('/api/auth', createRateLimiter(15 * 60 * 1000, 10, 'Too many authentication requests', whitelistedIPs));
app.use('/api/chat/send', createRateLimiter(1 * 60 * 1000, 60, 'Too many messages sent'));
app.use('/api/notifications', createRateLimiter(1 * 60 * 1000, 30, 'Too many notification requests'));
app.use('/api', createRateLimiter(1 * 60 * 1000, 200, 'Too many API requests'));

// ✅ Connection Management
const activeConnections = new Map();
const socketToUser = new Map();
const contactToUser = new Map();
const connectionStats = {
  totalConnections: 0,
  currentConnections: 0,
  peakConnections: 0,
  lastReset: Date.now()
};

// ✅ Enhanced Authentication Middleware
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];
  
  // Check for API key authentication (for server-to-server)
  if (apiKey && process.env.API_KEYS?.split(',').includes(apiKey)) {
    req.isApiKey = true;
    return next();
  }
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    if (ENABLE_METRICS) {
      authenticationAttempts.labels('bearer_token', 'failed', 'missing_header').inc();
    }
    return res.status(401).json({ 
      error: 'Authorization header required',
      code: 'AUTH_HEADER_MISSING'
    });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    if (ENABLE_METRICS) {
      authenticationAttempts.labels('bearer_token', 'failed', 'missing_token').inc();
    }
    return res.status(401).json({ 
      error: 'Token missing',
      code: 'TOKEN_MISSING'
    });
  }

  try {
    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(token, true); // Check revoked tokens
    req.user = decodedToken;
    req.userId = decodedToken.uid;
    
    // Get user profile from Firestore
    const userDoc = await db.collection('users').doc(req.userId).get();
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_fetch', 'success', 'users').inc();
    }
    
    if (!userDoc.exists) {
      if (ENABLE_METRICS) {
        authenticationAttempts.labels('bearer_token', 'failed', 'user_not_found').inc();
      }
      return res.status(404).json({ 
        error: 'User profile not found',
        code: 'USER_NOT_FOUND'
      });
    }
    
    const profileData = userDoc.data();
    req.profile = profileData;
    req.contactId = profileData.contactId || req.userId;
    
    // Update user activity
    await updateUserActivity(req.userId);
    
    if (ENABLE_METRICS) {
      authenticationAttempts.labels('bearer_token', 'success', 'valid').inc();
    }
    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('auth_verify', 'error', 'auth').inc();
    }
    
    let errorMessage = 'Invalid or expired token';
    let errorCode = 'TOKEN_INVALID';
    let failureReason = 'invalid_token';
    
    if (error.code === 'auth/id-token-expired') {
      errorMessage = 'Token expired';
      errorCode = 'TOKEN_EXPIRED';
      failureReason = 'expired_token';
    } else if (error.code === 'auth/id-token-revoked') {
      errorMessage = 'Token revoked';
      errorCode = 'TOKEN_REVOKED';
      failureReason = 'revoked_token';
    } else if (error.code === 'auth/argument-error') {
      errorMessage = 'Invalid token format';
      errorCode = 'TOKEN_FORMAT_INVALID';
      failureReason = 'format_invalid';
    }
    
    if (ENABLE_METRICS) {
      authenticationAttempts.labels('bearer_token', 'failed', failureReason).inc();
    }
    return res.status(401).json({ 
      error: errorMessage,
      code: errorCode
    });
  }
}

// ✅ Enhanced Helper Functions
async function updateUserActivity(userId) {
  try {
    await db.collection('users').doc(userId).update({
      lastActive: FieldValue.serverTimestamp(),
      lastActiveIP: null, // Don't store IP for privacy
      lastActiveUserAgent: null // Don't store user agent for privacy
    });
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_update', 'success', 'users').inc();
    }
  } catch (error) {
    console.error('❌ Error updating user activity:', error);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_update', 'error', 'users').inc();
    }
  }
}

async function findUserByContactId(contactId) {
  try {
    // First check cache
    const cachedUserId = contactToUser.get(contactId);
    if (cachedUserId) {
      const userDoc = await db.collection('users').doc(cachedUserId).get();
      if (userDoc.exists) {
        return {
          id: cachedUserId,
          data: userDoc.data()
        };
      } else {
        // Remove from cache if user doesn't exist
        contactToUser.delete(contactId);
      }
    }
    
    // Query Firestore
    const userQuery = await db.collection('users')
      .where('contactId', '==', contactId)
      .limit(1)
      .get();
    
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_query', 'success', 'users').inc();
    }
    
    if (userQuery.empty) {
      return null;
    }
    
    const userDoc = userQuery.docs[0];
    const result = {
      id: userDoc.id,
      data: userDoc.data()
    };
    
    // Cache the result
    contactToUser.set(contactId, userDoc.id);
    
    return result;
  } catch (error) {
    console.error('❌ Error finding user by contactId:', error);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_query', 'error', 'users').inc();
    }
    return null;
  }
}

// ✅ Enhanced API Routes

// Health check endpoint with comprehensive status
app.get('/api/health', async (req, res) => {
  try {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
      uptime: Math.floor(process.uptime()),
      host: HOST,
      port: PORT,
      connections: {
        active: activeConnections.size,
        peak: connectionStats.peakConnections,
        total: connectionStats.totalConnections
      },
      services: {
        notifications: 'enabled',
        metrics: ENABLE_METRICS ? 'enabled' : 'disabled',
        compression: 'enabled',
        rateLimit: 'enabled'
      },
      memory: process.memoryUsage(),
      performance: {
        nodeVersion: process.version,
        platform: process.platform,
        loadAverage: process.loadavg ? process.loadavg() : null
      }
    };

    // Test Firebase connection
    try {
      await db.collection('_health').doc('server').set({
        lastCheck: FieldValue.serverTimestamp(),
        status: 'healthy'
      });
      healthStatus.firebase = 'connected';
    } catch (error) {
      healthStatus.firebase = 'error';
      healthStatus.firebaseError = error.message;
    }

    // Test notification service
    try {
      const notifStatus = await notificationService.healthCheck();
      healthStatus.notificationService = notifStatus.status;
    } catch (error) {
      healthStatus.notificationService = 'error';
    }

    res.json(healthStatus);
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Metrics endpoint
if (ENABLE_METRICS) {
  app.get('/metrics', async (req, res) => {
    try {
      // Update resource usage metrics
      const memUsage = process.memoryUsage();
      resourceUsage.labels('memory_rss').set(memUsage.rss);
      resourceUsage.labels('memory_heap_used').set(memUsage.heapUsed);
      resourceUsage.labels('memory_heap_total').set(memUsage.heapTotal);
      resourceUsage.labels('uptime').set(process.uptime());
      
      res.set('Content-Type', register.contentType);
      const metrics = await register.metrics();
      res.end(metrics);
    } catch (error) {
      console.error('❌ Error generating metrics:', error);
      res.status(500).end(error.toString());
    }
  });
}

// ✅ Enhanced Authentication Endpoints
app.post('/api/auth/login', async (req, res) => {
  const { idToken, contactId, deviceId, fcmToken, platform } = req.body;
  
  if (!idToken || !contactId || !deviceId) {
    return res.status(400).json({ 
      error: 'Missing required fields: idToken, contactId, deviceId',
      code: 'MISSING_FIELDS'
    });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;
    
    console.log(`🔐 Login: ${userId}, contactId: ${contactId}, device: ${deviceId}`);

    const updateData = {
      isOnline: true,
      lastSeen: FieldValue.serverTimestamp(),
      lastActive: FieldValue.serverTimestamp(),
      lastDevice: deviceId,
      contactId: contactId,
      loginCount: FieldValue.increment(1)
    };

    if (fcmToken) {
      // Validate FCM token before storing
      const tokenValidation = await notificationService.validateToken(fcmToken, userId);
      if (tokenValidation.isValid) {
        updateData.fcmToken = fcmToken;
        updateData.platform = platform || (req.headers['user-agent']?.includes('iPhone') ? 'ios' : 'android');
        updateData.lastTokenUpdate = FieldValue.serverTimestamp();
      } else {
        console.warn(`⚠️ Invalid FCM token provided during login: ${fcmToken.substring(0, 20)}...`);
      }
    }

    await db.collection('users').doc(userId).update(updateData);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_login', 'success', 'users').inc();
    }

    // Cache contact to user mapping
    contactToUser.set(contactId, userId);

    res.json({ 
      success: true,
      userId,
      contactId,
      message: 'Login successful',
      fcmTokenValid: fcmToken ? tokenValidation?.isValid || false : null
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('user_login', 'error', 'users').inc();
    }
    return res.status(401).json({ 
      error: 'Invalid Firebase token',
      code: 'INVALID_TOKEN'
    });
  }
});

// ✅ Enhanced Message Sending Endpoint
app.post('/api/chat/send', authenticate, async (req, res) => {
  const { recipientContactId, content, messageType = 'text', silent = false, priority = 'normal' } = req.body;
  
  if (!recipientContactId || !content?.trim()) {
    return res.status(400).json({ 
      error: 'recipientContactId and content are required',
      code: 'MISSING_FIELDS'
    });
  }

  if (content.trim().length > 5000) {
    return res.status(400).json({ 
      error: 'Message content too long (max 5000 characters)',
      code: 'CONTENT_TOO_LONG'
    });
  }

  // Prevent self-messaging
  if (recipientContactId === req.contactId) {
    return res.status(400).json({
      error: 'Cannot send message to yourself',
      code: 'INVALID_RECIPIENT'
    });
  }

  try {
    const messageId = uuidv4();
    const timestamp = FieldValue.serverTimestamp();
    const messageData = {
      id: messageId,
      senderContactId: req.contactId,
      recipientContactId,
      content: content.trim(),
      messageType,
      timestamp,
      status: 'sent',
      silent,
      priority,
      edited: false,
      deleted: false
    };

    console.log(`📨 Message: ${req.contactId} → ${recipientContactId} (${messageType})`);

    // Find recipient user
    const recipientUser = await findUserByContactId(recipientContactId);
    
    if (!recipientUser) {
      if (ENABLE_METRICS) {
        totalMessages.labels(messageType, 'recipient_not_found', req.platform || 'unknown').inc();
      }
      return res.status(404).json({ 
        error: 'Recipient not found',
        code: 'RECIPIENT_NOT_FOUND'
      });
    }

    const recipientUserId = recipientUser.id;
    const recipientData = recipientUser.data;

    // Use batch write for atomicity
    const batch = db.batch();
    
    // Save message for sender
    const senderChatRef = db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .doc(recipientContactId)
      .collection('messages')
      .doc(messageId);
    batch.set(senderChatRef, messageData);

    // Save message for recipient
    const recipientChatRef = db.collection('users')
      .doc(recipientUserId)
      .collection('chats')
      .doc(req.contactId)
      .collection('messages')
      .doc(messageId);
    batch.set(recipientChatRef, messageData);

    // Update sender's chat metadata
    const senderMetaRef = db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .doc(recipientContactId);
    batch.set(senderMetaRef, {
      contactId: recipientContactId,
      displayName: recipientData.displayName || recipientContactId,
      photoURL: recipientData.photoURL || null,
      lastMessage: content.trim(),
      lastMessageTime: timestamp,
      unreadCount: 0,
      isOnline: recipientData.isOnline || false,
      updatedAt: timestamp
    }, { merge: true });

    // Update recipient's chat metadata
    const recipientMetaRef = db.collection('users')
      .doc(recipientUserId)
      .collection('chats')
      .doc(req.contactId);
    batch.set(recipientMetaRef, {
      contactId: req.contactId,
      displayName: req.profile.displayName || req.contactId,
      photoURL: req.profile.photoURL || null,
      lastMessage: content.trim(),
      lastMessageTime: timestamp,
      unreadCount: FieldValue.increment(1),
      isOnline: true,
      updatedAt: timestamp
    }, { merge: true });

    // Commit batch
    await batch.commit();
    if (ENABLE_METRICS) {
      firebaseOperations.labels('message_batch', 'success', 'chats').inc();
    }

    // Real-time delivery via WebSocket
    const recipientConnection = [...activeConnections.values()]
      .find(conn => conn.contactId === recipientContactId);
    
    let recipientOnline = false;
    let notificationSent = false;

    if (recipientConnection && recipientConnection.socketId) {
      const recipientSocket = io.sockets.sockets.get(recipientConnection.socketId);
      if (recipientSocket && recipientSocket.connected) {
        recipientSocket.emit('new_message', {
          ...messageData,
          timestamp: new Date().toISOString() // Convert to ISO string for JSON
        });
        recipientOnline = true;
        console.log(`⚡ Real-time delivery: ${recipientContactId}`);

        // Send delivery receipt
        recipientSocket.emit('message_delivered', { messageId });
      }
    }

    // ✅ NEW CODE: Send push notification via Expo if recipient is offline or not on silent mode
if ((!recipientOnline || !silent) && !recipientData.notificationsDisabled) {
  // ✅ Support both Expo and legacy FCM tokens
  const pushToken = recipientData.expoPushToken || recipientData.fcmToken;
  
  if (pushToken) {
    try {
      const notificationData = {
        title: req.profile.displayName || req.contactId,
        body: messageType === 'text' 
          ? (content.length > 50 ? content.substring(0, 47) + '...' : content.trim())
          : `Sent a ${messageType}`,
        data: {
          type: 'chat_message',
          contactId: req.contactId,
          messageId: messageId,
          timestamp: new Date().toISOString(),
          priority: priority
        },
        token: pushToken, // ✅ Use combined token
        priority: priority === 'high' ? 'high' : 'normal'
      };
      
      const notificationResult = await notificationService.sendNotification(notificationData);
      notificationSent = notificationResult.success;
      
      if (ENABLE_METRICS) {
        notificationsSent.labels(
          recipientData.platform || 'unknown', 
          notificationResult.success ? 'success' : 'failed',
          'chat_message'
        ).inc();
      }
      
      console.log(`🔔 Expo notification ${notificationResult.success ? 'sent' : 'failed'} to ${recipientContactId}`);
    } catch (notifError) {
      console.error('❌ Failed to send Expo notification:', notifError);
      if (ENABLE_METRICS) {
        notificationsSent.labels(recipientData.platform || 'unknown', 'error', 'chat_message').inc();
      }
    }
  } else {
    console.log(`⚠️ No push token found for recipient: ${recipientContactId}`);
  }
}

    if (ENABLE_METRICS) {
      totalMessages.labels(messageType, 'success', req.platform || 'unknown').inc();
    }

    res.json({ 
      success: true,
      messageId,
      timestamp: new Date().toISOString(),
      status: 'sent',
      recipientOnline,
      notificationSent,
      priority
    });

  } catch (error) {
    console.error('❌ Send message error:', error);
    if (ENABLE_METRICS) {
      totalMessages.labels(messageType || 'text', 'error', req.platform || 'unknown').inc();
      firebaseOperations.labels('message_batch', 'error', 'chats').inc();
    }
    res.status(500).json({ 
      error: 'Failed to send message',
      code: 'MESSAGE_SEND_FAILED',
      messageId: null
    });
  }
});

// ✅ NEW CODE
app.post('/api/notifications/register', authenticate, async (req, res) => {
  const { fcmToken: expoPushToken, platform, deviceId, appVersion } = req.body; // ✅ Changed
  
  if (!expoPushToken) {
    return res.status(400).json({ 
      error: 'Expo push token is required',
      expectedFormat: 'ExponentPushToken[...]'
    });
  }

  // ✅ ADD: Validate Expo token format
  if (!Expo.isExpoPushToken(expoPushToken)) {
    return res.status(400).json({ 
      error: 'Invalid Expo push token format',
      received: expoPushToken?.substring(0, 30) + '...',
      expectedFormat: 'ExponentPushToken[...]'
    });
  }
// ✅ NEW CODE  
await updateDoc(userRef, {
  expoPushToken: expoPushToken,  // ✅ New field name
  fcmToken: expoPushToken,       // ✅ Keep for backward compatibility
  platform,
  tokenProvider: 'expo',         // ✅ Mark as using Expo
  // ... other existing fields
});
// ✅ NEW CODE: Send Custom Notification Endpoint
app.post('/api/notifications/send', authenticate, async (req, res) => {
  const { targetContactId, title, body, data = {}, priority = 'normal' } = req.body;
  
  // Validate required fields
  if (!targetContactId || !title || !body) {
    return res.status(400).json({ 
      error: 'targetContactId, title, and body are required',
      received: { targetContactId, title: !!title, body: !!body }
    });
  }

  try {
    // ✅ Find target user by contactId
    const targetUser = await getUserByContactId(targetContactId);
    if (!targetUser) {
      return res.status(404).json({ 
        error: 'Target user not found',
        contactId: targetContactId
      });
    }

    // ✅ Get push token (support both Expo and legacy FCM)
    const pushToken = targetUser.expoPushToken || targetUser.fcmToken;
    if (!pushToken) {
      return res.status(400).json({ 
        error: 'User has no push token registered',
        userId: targetUser.id
      });
    }

    // ✅ Send notification via Expo service
    const result = await notificationService.sendNotification({
      token: pushToken,
      title,
      body,
      data: {
        ...data,
        type: 'custom_notification',
        senderContactId: req.contactId,
        timestamp: new Date().toISOString()
      },
      priority
    });

    // ✅ Track metrics if enabled
    if (ENABLE_METRICS) {
      notificationsSent.labels(
        targetUser.platform || 'unknown',
        result.success ? 'success' : 'failed',
        'custom_notification'
      ).inc();
    }

    console.log(`🔔 Custom notification ${result.success ? 'sent' : 'failed'}: ${req.contactId} -> ${targetContactId}`);

    // ✅ Return comprehensive response
    res.json({
      success: result.success,
      message: result.success ? 'Notification sent successfully' : 'Failed to send notification',
      provider: 'expo',
      messageId: result.messageId,
      targetContactId,
      timestamp: new Date().toISOString(),
      error: result.success ? undefined : result.error
    });

  } catch (error) {
    console.error('❌ Custom notification error:', error);
    
    // ✅ Track error metrics
    if (ENABLE_METRICS) {
      notificationsSent.labels('unknown', 'error', 'custom_notification').inc();
    }
    
    res.status(500).json({ 
      error: 'Failed to send notification',
      details: error.message,
      provider: 'expo',
      timestamp: new Date().toISOString()
    });
  }
});


app.post('/api/notifications/validate', authenticate, async (req, res) => {
  const { fcmToken } = req.body;
  
  if (!fcmToken) {
    return res.status(400).json({ error: 'FCM token required' });
  }

  try {
    const validation = await notificationService.validateToken(fcmToken, req.userId);
    
    res.json({
      valid: validation.isValid,
      reason: validation.reason,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Error validating FCM token:', error);
    res.status(500).json({ error: 'Token validation failed' });
  }
});

// ✅ Enhanced Chat Endpoints
app.get('/api/chats', authenticate, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = parseInt(req.query.offset) || 0;

    let query = db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .orderBy('lastMessageTime', 'desc')
      .limit(limit);

    if (offset > 0) {
      const offsetDoc = await db.collection('users')
        .doc(req.userId)
        .collection('chats')
        .orderBy('lastMessageTime', 'desc')
        .limit(offset)
        .get();
      
      if (!offsetDoc.empty) {
        const lastDoc = offsetDoc.docs[offsetDoc.docs.length - 1];
        query = query.startAfter(lastDoc);
      }
    }

    const chatsSnapshot = await query.get();
    const chats = [];
    
    chatsSnapshot.forEach(doc => {
      const chatData = doc.data();
      chats.push({
        contactId: chatData.contactId,
        displayName: chatData.displayName || chatData.contactId,
        photoURL: chatData.photoURL,
        lastMessage: chatData.lastMessage || '',
        lastMessageTime: chatData.lastMessageTime?.toDate?.()?.toISOString() || null,
        unreadCount: chatData.unreadCount || 0,
        isOnline: chatData.isOnline || false,
        updatedAt: chatData.updatedAt?.toDate?.()?.toISOString() || null
      });
    });

    if (ENABLE_METRICS) {
      firebaseOperations.labels('chats_fetch', 'success', 'chats').inc();
    }
    
    console.log(`📬 Retrieved ${chats.length} chats for ${req.contactId}`);
    
    res.json({ 
      chats, 
      count: chats.length,
      hasMore: chats.length === limit,
      offset: offset + chats.length
    });
  } catch (error) {
    console.error('❌ Get chats error:', error);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('chats_fetch', 'error', 'chats').inc();
    }
    res.status(500).json({ 
      error: 'Failed to fetch chats',
      code: 'CHATS_FETCH_FAILED'
    });
  }
});

app.get('/api/chat/:contactId/messages', authenticate, async (req, res) => {
  const { contactId } = req.params;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const before = req.query.before; // Timestamp for pagination

  try {
    let query = db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .doc(contactId)
      .collection('messages')
      .orderBy('timestamp', 'desc')
      .limit(limit);

    if (before) {
      const beforeDate = new Date(before);
      query = query.where('timestamp', '<', beforeDate);
    }

    const messagesSnapshot = await query.get();
    const messages = [];
    
    messagesSnapshot.forEach(doc => {
      const data = doc.data();
      messages.push({
        id: doc.id,
        ...data,
        timestamp: data.timestamp?.toDate?.()?.toISOString() || new Date().toISOString()
      });
    });

    // Reverse to get chronological order (oldest first)
    messages.reverse();

    if (ENABLE_METRICS) {
      firebaseOperations.labels('messages_fetch', 'success', 'messages').inc();
    }
    
    console.log(`📬 Retrieved ${messages.length} messages for ${req.contactId} ↔ ${contactId}`);
    
    res.json({ 
      messages, 
      count: messages.length,
      hasMore: messages.length === limit,
      nextBefore: messages.length > 0 ? messages[0].timestamp : null
    });
  } catch (error) {
    console.error('❌ Get messages error:', error);
    if (ENABLE_METRICS) {
      firebaseOperations.labels('messages_fetch', 'error', 'messages').inc();
    }
    res.status(500).json({ 
      error: 'Failed to fetch messages',
      code: 'MESSAGES_FETCH_FAILED'
    });
  }
});

// ✅ Enhanced WebSocket Connection Handling
io.on('connection', (socket) => {
  console.log(`🔌 Socket connected: ${socket.id}`);
  connectionStats.totalConnections++;
  connectionStats.currentConnections = activeConnections.size + 1;
  
  if (connectionStats.currentConnections > connectionStats.peakConnections) {
    connectionStats.peakConnections = connectionStats.currentConnections;
  }
  
  if (ENABLE_METRICS) {
    activeWebSocketConnections.inc();
  }

  // Connection timeout
  const connectionTimeout = setTimeout(() => {
    if (!socket.authenticated) {
      console.warn(`⚠️ Socket ${socket.id} authentication timeout`);
      socket.emit('auth_error', { error: 'Authentication timeout' });
      socket.disconnect(true);
    }
  }, 30000); // 30 second timeout

  socket.on('authenticate', async (data) => {
    try {
      clearTimeout(connectionTimeout);
      
      const { token, contactId, deviceId, appVersion } = data;
      
      if (!token || !contactId) {
        socket.emit('auth_error', { error: 'Token and contactId required' });
        return;
      }

      // Verify Firebase token
      const decodedToken = await admin.auth().verifyIdToken(token);
      const userId = decodedToken.uid;

      // Handle existing connections for this user
      if (activeConnections.has(userId)) {
        const existingConnection = activeConnections.get(userId);
        if (existingConnection.socketId && existingConnection.socketId !== socket.id) {
          const oldSocket = io.sockets.sockets.get(existingConnection.socketId);
          if (oldSocket) {
            oldSocket.emit('connection_replaced', { reason: 'New connection established' });
            oldSocket.disconnect(true);
          }
          socketToUser.delete(existingConnection.socketId);
        }
      }

      // Store connection info
      const connectionInfo = { 
        socketId: socket.id, 
        contactId,
        deviceId: deviceId || 'unknown',
        appVersion: appVersion || 'unknown',
        lastActive: Date.now(),
        connectedAt: new Date().toISOString(),
        authenticated: true
      };
      
      activeConnections.set(userId, connectionInfo);
      socketToUser.set(socket.id, userId);
      contactToUser.set(contactId, userId);
      socket.authenticated = true;
      socket.userId = userId;
      socket.contactId = contactId;

      // Update user online status
      await db.collection('users').doc(userId).update({
        isOnline: true,
        lastActive: FieldValue.serverTimestamp(),
        lastConnection: FieldValue.serverTimestamp()
      });
      
      socket.emit('authenticated', { 
        success: true, 
        contactId,
        serverId: socket.id 
      });
      socket.broadcast.emit('user_online', { contactId });
      
      console.log(`⚡ Socket authenticated: ${contactId} (${socket.id})`);
    } catch (error) {
      console.error('❌ Socket authentication error:', error);
      if (ENABLE_METRICS) {
        connectionErrors.labels('auth_failed', 'websocket').inc();
      }
      socket.emit('auth_error', { error: 'Authentication failed' });
      socket.disconnect(true);
    }
  });

  // Enhanced typing indicators
  socket.on('typing_start', (data) => {
    const userId = socketToUser.get(socket.id);
    if (userId && data.contactId && socket.authenticated) {
      const connection = activeConnections.get(userId);
      if (connection) {
        // Update last active
        connection.lastActive = Date.now();
        
        socket.broadcast.emit('typing_start', { 
          contactId: connection.contactId,
          targetContactId: data.contactId,
          timestamp: new Date().toISOString()
        });
      }
    }
  });

  socket.on('typing_stop', (data) => {
    const userId = socketToUser.get(socket.id);
    if (userId && data.contactId && socket.authenticated) {
      const connection = activeConnections.get(userId);
      if (connection) {
        socket.broadcast.emit('typing_stop', { 
          contactId: connection.contactId,
          targetContactId: data.contactId,
          timestamp: new Date().toISOString()
        });
      }
    }
  });

  // Enhanced message status handling
  socket.on('message_delivered', async (data) => {
    const { messageId, contactId } = data;
    if (messageId && socket.authenticated) {
      try {
        // Update message status in Firebase
        await db.collection('messageStatus').doc(messageId).set({
          status: 'delivered',
          deliveredAt: FieldValue.serverTimestamp(),
          deliveredBy: socket.contactId
        }, { merge: true });
        
        // Notify sender
        socket.broadcast.emit('message_status_updated', { 
          messageId, 
          status: 'delivered',
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        console.error('❌ Error updating message delivery status:', error);
      }
    }
  });

  socket.on('message_read', async (data) => {
    const { messageId, contactId } = data;
    if (messageId && socket.authenticated) {
      try {
        await db.collection('messageStatus').doc(messageId).set({
          status: 'read',
          readAt: FieldValue.serverTimestamp(),
          readBy: socket.contactId
        }, { merge: true });
        
        socket.broadcast.emit('message_status_updated', { 
          messageId, 
          status: 'read',
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        console.error('❌ Error updating message read status:', error);
      }
    }
  });

  // Presence heartbeat
  socket.on('heartbeat', () => {
    const userId = socketToUser.get(socket.id);
    if (userId && socket.authenticated) {
      const connection = activeConnections.get(userId);
      if (connection) {
        connection.lastActive = Date.now();
      }
      socket.emit('heartbeat_ack', { timestamp: Date.now() });
    }
  });

  // Enhanced disconnect handling
  socket.on('disconnect', async (reason) => {
    console.log(`🔌 Socket disconnected: ${socket.id}, reason: ${reason}`);
    
    connectionStats.currentConnections = Math.max(0, activeConnections.size - 1);
    
    if (ENABLE_METRICS) {
      activeWebSocketConnections.dec();
    }

    const userId = socketToUser.get(socket.id);
    if (userId) {
      const connection = activeConnections.get(userId);
      if (connection && connection.socketId === socket.id) {
        try {
          // Update user offline status
          await db.collection('users').doc(userId).update({
            isOnline: false,
            lastSeen: FieldValue.serverTimestamp(),
            lastDisconnectReason: reason
          });
          
          socket.broadcast.emit('user_offline', { 
            contactId: connection.contactId,
            lastSeen: new Date().toISOString()
          });
          
          // Clean up connection mappings
          contactToUser.delete(connection.contactId);
        } catch (error) {
          console.error('❌ Error updating offline status:', error);
        }
      }
      
      activeConnections.delete(userId);
      socketToUser.delete(socket.id);
    }
  });

  // Error handling
  socket.on('error', (error) => {
    console.error(`❌ Socket error ${socket.id}:`, error);
    if (ENABLE_METRICS) {
      connectionErrors.labels('socket_error', 'websocket').inc();
    }
  });
});

// ✅ Enhanced Error Handling Middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  
  if (ENABLE_METRICS) {
    connectionErrors.labels('unhandled_error', 'http').inc();
  }
  
  // Don't leak error details in production
  const errorMessage = IS_PRODUCTION ? 'Internal server error' : error.message;
  const errorStack = IS_PRODUCTION ? undefined : error.stack;
  
  res.status(error.status || 500).json({ 
    error: errorMessage,
    code: 'INTERNAL_ERROR',
    stack: errorStack,
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  console.warn(`❌ 404 - Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    error: 'Route not found',
    code: 'ROUTE_NOT_FOUND',
    path: req.originalUrl,
    method: req.method
  });
});

// ✅ Enhanced Maintenance Functions

// Self-ping to prevent sleep (for free hosting services)
if (process.env.ENABLE_SELF_PING !== 'false') {
  setInterval(async () => {
    try {
      const externalUrl = getExternalUrl();
      const healthUrl = `${externalUrl}/api/health`;
      
      console.log(`🏓 Self-ping to: ${healthUrl}`);
      
      const response = await fetch(healthUrl, {
        method: 'GET',
        timeout: 10000,
        headers: {
          'User-Agent': 'SecureLink-Server-SelfPing/1.0'
        }
      });
      
      if (response.ok) {
        console.log('🏓 Self-ping successful');
      } else {
        console.warn(`⚠️ Self-ping failed with status: ${response.status}`);
      }
    } catch (error) {
      console.warn(`⚠️ Self-ping error: ${error.message}`);
    }
  }, 6 * 60 * 1000); // Every 6 minutes
}

// Enhanced connection cleanup
setInterval(() => {
  const now = Date.now();
  const inactiveThreshold = 15 * 60 * 1000; // 15 minutes
  let cleanedCount = 0;
  
  for (const [userId, connection] of activeConnections.entries()) {
    if (now - connection.lastActive > inactiveThreshold) {
      const socket = io.sockets.sockets.get(connection.socketId);
      if (socket) {
        socket.emit('connection_timeout', { reason: 'Inactive connection' });
        socket.disconnect(true);
      }
      activeConnections.delete(userId);
      socketToUser.delete(connection.socketId);
      contactToUser.delete(connection.contactId);
      cleanedCount++;
    }
  }
  
  if (cleanedCount > 0) {
    console.log(`🧹 Cleaned up ${cleanedCount} inactive connections`);
  }
  
  connectionStats.currentConnections = activeConnections.size;
}, 5 * 60 * 1000); // Every 5 minutes

// Update WebSocket connections gauge
if (ENABLE_METRICS) {
  setInterval(() => {
    activeWebSocketConnections.set(activeConnections.size);
  }, 30 * 1000); // Every 30 seconds
}

// Periodic notification service cleanup
setInterval(() => {
  notificationService.performTokenCleanup();
}, 60 * 60 * 1000); // Every hour

// Memory usage monitoring
setInterval(() => {
  const memUsage = process.memoryUsage();
  const memUsageMB = {
    rss: Math.round(memUsage.rss / 1024 / 1024),
    heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
    heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
    external: Math.round(memUsage.external / 1024 / 1024)
  };
  
  if (memUsageMB.heapUsed > 500) { // Warning if heap usage > 500MB
    console.warn(`⚠️ High memory usage detected:`, memUsageMB);
  }
  
  // Force garbage collection in development
  if (!IS_PRODUCTION && global.gc) {
    global.gc();
  }
}, 2 * 60 * 1000); // Every 2 minutes

// ✅ Enhanced Graceful Shutdown
const shutdown = async (signal) => {
  console.log(`\n🛑 ${signal} received, shutting down gracefully...`);
  
  const shutdownTimeout = setTimeout(() => {
    console.log('⚠️ Forced shutdown due to timeout');
    process.exit(1);
  }, 30000); // 30 second timeout

  try {
    // Stop accepting new connections
    console.log('📡 Stopping new connections...');
    server.close();

    // Disconnect all WebSocket connections
    console.log('🔌 Disconnecting WebSocket clients...');
    io.emit('server_shutdown', { message: 'Server is shutting down' });
    
    // Give clients time to receive the message
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    io.close(() => {
      console.log('📡 WebSocket server closed');
    });

    // Update all connected users to offline status
    console.log('👥 Updating user statuses...');
    const batch = db.batch();
    for (const [userId, connection] of activeConnections.entries()) {
      const userRef = db.collection('users').doc(userId);
      batch.update(userRef, {
        isOnline: false,
        lastSeen: FieldValue.serverTimestamp(),
        lastDisconnectReason: 'server_shutdown'
      });
    }
    
    if (activeConnections.size > 0) {
      await batch.commit();
      console.log(`✅ Updated ${activeConnections.size} user statuses`);
    }

    // Clear connection maps
    activeConnections.clear();
    socketToUser.clear();
    contactToUser.clear();

    console.log('✅ Graceful shutdown completed');
    clearTimeout(shutdownTimeout);
    process.exit(0);
    
  } catch (error) {
    console.error('❌ Error during shutdown:', error);
    clearTimeout(shutdownTimeout);
    process.exit(1);
  }
};

// Process signal handlers
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Enhanced uncaught exception handling
// ✅ FIXED: Add conditional check for connectionErrors
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  
  // ✅ Only increment counter if metrics are enabled and defined
  if (ENABLE_METRICS && typeof connectionErrors !== 'undefined') {
    connectionErrors.labels('uncaught_exception', 'process').inc();
  }
  
  // Give time to log the error, then exit
  setTimeout(() => process.exit(1), 1000);
});

// ✅ FIXED: Add conditional check for unhandled rejection
process.on('unhandledRejection', (reason, promise) => {
  console.error('🚫 Unhandled Rejection at:', promise, 'reason:', reason);
  
  // ✅ Only increment counter if metrics are enabled and defined
  if (ENABLE_METRICS && typeof connectionErrors !== 'undefined') {
    connectionErrors.labels('unhandled_rejection', 'process').inc();
  }
  
  // Don't exit on unhandled rejection in production, just log it
  if (!IS_PRODUCTION) {
    setTimeout(() => process.exit(1), 1000);
  }
});


// ✅ Enhanced Server Startup
const startServer = async () => {
  try {
    // Test Firebase connection before starting
    console.log('🔥 Testing Firebase connection...');
    await db.collection('_server').doc('startup').set({
      timestamp: FieldValue.serverTimestamp(),
      version: process.env.npm_package_version || '1.0.0',
      environment: NODE_ENV,
      host: HOST,
      port: PORT
    });
    console.log('✅ Firebase connection successful');

    // Test notification service
    console.log('🔔 Testing notification service...');
    const notifHealth = await notificationService.healthCheck();
    console.log(`✅ Notification service: ${notifHealth.status}`);

    // Start server
    server.listen(PORT, HOST, () => {
      console.log('\n🚀 ===== SecureLink Server Started =====');
      console.log(`🌐 Server URL: http://${HOST}:${PORT}`);
      console.log(`🌍 External URL: ${getExternalUrl()}`);
      console.log(`📱 Environment: ${NODE_ENV}`);
      console.log(`🔔 Push notifications: enabled`);
      console.log(`⚡ WebSocket: enabled`);
      console.log(`🛡️ Security: enabled`);
      console.log(`📊 Prometheus metrics: ${ENABLE_METRICS ? 'enabled on /metrics' : 'disabled'}`);
      console.log(`🏓 Self-ping: ${process.env.ENABLE_SELF_PING !== 'false' ? 'enabled (every 6 minutes)' : 'disabled'}`);
      console.log(`🧹 Auto-cleanup: enabled`);
      console.log(`📈 Max connections: ${MAX_CONNECTIONS}`);
      console.log('==========================================\n');
      
      console.log('🎉 Server is ready to accept connections!');
    });

  } catch (error) {
    console.error('💥 Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

// ✅ Export for testing
export { 
  app, 
  server, 
  io, 
  activeConnections, 
  socketToUser, 
  contactToUser,
  connectionStats,
  register,
  notificationService
};


