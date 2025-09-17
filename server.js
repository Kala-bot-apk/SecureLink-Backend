// server.js
import express from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import bodyParser from 'body-parser';
import { createServer } from 'http';
import { Server } from 'socket.io';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { admin, db } from './firebaseAdmin.js';
import { NotificationService } from './services/notificationService.js';
// ✅ NEW: Import Prometheus client
import client from 'prom-client';

dotenv.config();

const app = express();
const server = createServer(app);

// Configuration
const HOST = 'https://securelink-backend-e65c.onrender.com';
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || 'development';

// ✅ NEW: Prometheus Metrics Setup
const register = new client.Registry();

// Collect default Node.js metrics
client.collectDefaultMetrics({ 
  register,
  timeout: 10000,
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
  eventLoopMonitoringPrecision: 10,
});

// Custom metrics
const httpRequestDurationMicroseconds = new client.Histogram({
  name: 'http_request_duration_ms',
  help: 'Duration of HTTP requests in ms',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 5, 15, 50, 100, 200, 300, 400, 500, 1000, 2000, 5000]
});

const httpRequestTotal = new client.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

const activeWebSocketConnections = new client.Gauge({
  name: 'websocket_connections_active',
  help: 'Number of active WebSocket connections'
});

const totalMessages = new client.Counter({
  name: 'chat_messages_total',
  help: 'Total number of chat messages sent',
  labelNames: ['message_type', 'status']
});

const notificationsSent = new client.Counter({
  name: 'notifications_sent_total',
  help: 'Total number of push notifications sent',
  labelNames: ['platform', 'status']
});

const authenticationAttempts = new client.Counter({
  name: 'authentication_attempts_total',
  help: 'Total number of authentication attempts',
  labelNames: ['method', 'status']
});

const firebaseOperations = new client.Counter({
  name: 'firebase_operations_total',
  help: 'Total number of Firebase operations',
  labelNames: ['operation_type', 'status']
});

// Register custom metrics
register.registerMetric(httpRequestDurationMicroseconds);
register.registerMetric(httpRequestTotal);
register.registerMetric(activeWebSocketConnections);
register.registerMetric(totalMessages);
register.registerMetric(notificationsSent);
register.registerMetric(authenticationAttempts);
register.registerMetric(firebaseOperations);

// Socket.io setup
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: false
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// Initialize Notification Service
const notificationService = new NotificationService();

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false
}));

app.use(cors({
  origin: "*",
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// ✅ NEW: Prometheus metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const responseTimeInMs = Date.now() - start;
    const route = req.route ? req.route.path : req.path;
    
    httpRequestDurationMicroseconds
      .labels(req.method, route, res.statusCode.toString())
      .observe(responseTimeInMs);
    
    httpRequestTotal
      .labels(req.method, route, res.statusCode.toString())
      .inc();
  });
  
  next();
});

// Enhanced rate limiting
const createRateLimiter = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`⚠️ Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({ error: message });
  }
});

app.use('/api/auth', createRateLimiter(15 * 60 * 1000, 10, 'Too many auth requests'));
app.use('/api/chat/send', createRateLimiter(1 * 60 * 1000, 60, 'Too many messages'));
app.use('/api/notifications', createRateLimiter(1 * 60 * 1000, 30, 'Too many notification requests'));
app.use('/api', createRateLimiter(1 * 60 * 1000, 200, 'Too many requests'));

// Session management
const activeConnections = new Map(); // userId => { socketId, contactId, lastActive, deviceId }
const socketToUser = new Map(); // socketId => userId
const contactToUser = new Map(); // contactId => userId

// Enhanced authentication middleware
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    authenticationAttempts.labels('bearer_token', 'missing_header').inc();
    return res.status(401).json({ 
      error: 'Authorization header required',
      code: 'AUTH_HEADER_MISSING'
    });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    authenticationAttempts.labels('bearer_token', 'missing_token').inc();
    return res.status(401).json({ 
      error: 'Token missing',
      code: 'TOKEN_MISSING'
    });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    req.userId = decodedToken.uid;

    const userDoc = await db.collection('users').doc(req.userId).get();
    firebaseOperations.labels('user_fetch', 'success').inc();
    
    if (!userDoc.exists) {
      authenticationAttempts.labels('bearer_token', 'user_not_found').inc();
      return res.status(404).json({ 
        error: 'User profile not found',
        code: 'USER_NOT_FOUND'
      });
    }
    
    req.profile = userDoc.data();
    req.contactId = req.profile.contactId;

    // Update last active timestamp
    await updateUserActivity(req.userId);
    
    authenticationAttempts.labels('bearer_token', 'success').inc();
    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    firebaseOperations.labels('auth_verify', 'error').inc();
    
    let errorMessage = 'Invalid or expired token';
    let errorCode = 'TOKEN_INVALID';
    
    if (error.code === 'auth/id-token-expired') {
      errorMessage = 'Token expired';
      errorCode = 'TOKEN_EXPIRED';
    } else if (error.code === 'auth/argument-error') {
      errorMessage = 'Invalid token format';
      errorCode = 'TOKEN_FORMAT_INVALID';
    }
    
    authenticationAttempts.labels('bearer_token', 'failed').inc();
    return res.status(401).json({ 
      error: errorMessage,
      code: errorCode
    });
  }
}

// Helper function to update user activity
async function updateUserActivity(userId) {
  try {
    await db.collection('users').doc(userId).update({
      lastActive: admin.firestore.FieldValue.serverTimestamp()
    });
    firebaseOperations.labels('user_update', 'success').inc();
  } catch (error) {
    console.error('❌ Error updating user activity:', error);
    firebaseOperations.labels('user_update', 'error').inc();
  }
}

// Helper function to find user by contactId
async function findUserByContactId(contactId) {
  try {
    const userQuery = await db.collection('users')
      .where('contactId', '==', contactId)
      .limit(1)
      .get();
    
    firebaseOperations.labels('user_query', 'success').inc();
    return userQuery.empty ? null : {
      id: userQuery.docs[0].id,
      data: userQuery.docs[0].data()
    };
  } catch (error) {
    console.error('❌ Error finding user by contactId:', error);
    firebaseOperations.labels('user_query', 'error').inc();
    return null;
  }
}

// API Routes

// ✅ NEW: Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    const metrics = await register.metrics();
    res.end(metrics);
  } catch (error) {
    console.error('❌ Error generating metrics:', error);
    res.status(500).end(error.toString());
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    activeConnections: activeConnections.size,
    environment: NODE_ENV,
    host: HOST,
    port: PORT,
    version: '1.0.0',
    uptime: process.uptime(),
    notifications: 'enabled',
    metrics: 'enabled'
  });
});

// Authentication endpoints
app.post('/api/auth/login', async (req, res) => {
  const { idToken, contactId, deviceId, fcmToken } = req.body;

  if (!idToken || !contactId || !deviceId) {
    return res.status(400).json({ 
      error: 'Missing required fields: idToken, contactId, deviceId' 
    });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const userId = decodedToken.uid;

    console.log(`🔐 Login: ${userId}, contactId: ${contactId}, device: ${deviceId}`);

    // Update user status with FCM token
    const updateData = {
      isOnline: true,
      lastSeen: admin.firestore.FieldValue.serverTimestamp(),
      lastActive: admin.firestore.FieldValue.serverTimestamp(),
      lastDevice: deviceId,
      contactId: contactId
    };

    // Add FCM token if provided
    if (fcmToken) {
      updateData.fcmToken = fcmToken;
      updateData.platform = req.headers['user-agent']?.includes('iPhone') ? 'ios' : 'android';
      updateData.lastTokenUpdate = admin.firestore.FieldValue.serverTimestamp();
    }

    await db.collection('users').doc(userId).update(updateData);
    firebaseOperations.labels('user_login', 'success').inc();

    // Store contact to user mapping
    contactToUser.set(contactId, userId);

    res.json({ 
      success: true,
      userId,
      contactId,
      message: 'Login successful'
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    firebaseOperations.labels('user_login', 'error').inc();
    return res.status(401).json({ 
      error: 'Invalid Firebase token',
      code: 'INVALID_TOKEN'
    });
  }
});

// Enhanced chat message sending with notifications
app.post('/api/chat/send', authenticate, async (req, res) => {
  const { recipientContactId, content, messageType = 'text', silent = false } = req.body;

  if (!recipientContactId || !content?.trim()) {
    return res.status(400).json({ 
      error: 'recipientContactId and content are required' 
    });
  }

  if (content.trim().length > 1000) {
    return res.status(400).json({ 
      error: 'Message content too long (max 1000 characters)' 
    });
  }

  try {
    const messageId = uuidv4();
    const timestamp = admin.firestore.FieldValue.serverTimestamp();

    const messageData = {
      id: messageId,
      senderContactId: req.contactId,
      recipientContactId,
      content: content.trim(),
      messageType,
      timestamp,
      status: 'sent',
      silent
    };

    console.log(`📨 Message: ${req.contactId} → ${recipientContactId}`);

    // Find recipient user
    const recipientUser = await findUserByContactId(recipientContactId);
    
    if (!recipientUser) {
      totalMessages.labels(messageType, 'recipient_not_found').inc();
      return res.status(404).json({ 
        error: 'Recipient not found',
        code: 'RECIPIENT_NOT_FOUND'
      });
    }

    const recipientUserId = recipientUser.id;
    const recipientData = recipientUser.data;

    // Use Firestore batch for atomic operations
    const batch = db.batch();
    
    // Store message in sender's chat
    const senderChatRef = db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .doc(recipientContactId)
      .collection('messages')
      .doc(messageId);
    batch.set(senderChatRef, messageData);

    // Store message in recipient's chat
    const recipientChatRef = db.collection('users')
      .doc(recipientUserId)
      .collection('chats')
      .doc(req.contactId)
      .collection('messages')
      .doc(messageId);
    batch.set(recipientChatRef, messageData);

    // Update chat metadata for sender
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
      isOnline: recipientData.isOnline || false
    }, { merge: true });

    // Update chat metadata for recipient
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
      unreadCount: admin.firestore.FieldValue.increment(1),
      isOnline: true
    }, { merge: true });

    await batch.commit();
    firebaseOperations.labels('message_batch', 'success').inc();

    // Check if recipient is online via WebSocket
    const recipientConnection = [...activeConnections.values()]
      .find(conn => conn.contactId === recipientContactId);

    let recipientOnline = false;
    let notificationSent = false;

    if (recipientConnection && recipientConnection.socketId) {
      const recipientSocket = io.sockets.sockets.get(recipientConnection.socketId);
      if (recipientSocket) {
        recipientSocket.emit('new_message', messageData);
        recipientOnline = true;
        console.log(`⚡ Real-time delivery: ${recipientContactId}`);
      }
    }

    // Send push notification if recipient is offline or message is not silent
    if ((!recipientOnline || !silent) && recipientData.fcmToken) {
      try {
        const notificationData = {
          title: req.profile.displayName || req.contactId,
          body: messageType === 'text' ? content.trim() : `Sent a ${messageType}`,
          data: {
            type: 'chat_message',
            contactId: req.contactId,
            messageId: messageId,
            timestamp: new Date().toISOString()
          },
          token: recipientData.fcmToken
        };

        await notificationService.sendNotification(notificationData);
        notificationSent = true;
        notificationsSent.labels(recipientData.platform || 'unknown', 'success').inc();
        console.log(`🔔 Push notification sent to ${recipientContactId}`);
      } catch (notifError) {
        console.error('❌ Failed to send push notification:', notifError);
        notificationsSent.labels(recipientData.platform || 'unknown', 'error').inc();
      }
    }

    totalMessages.labels(messageType, 'success').inc();

    res.json({ 
      success: true,
      messageId,
      timestamp: new Date().toISOString(),
      status: 'sent',
      recipientOnline,
      notificationSent
    });

  } catch (error) {
    console.error('❌ Send message error:', error);
    totalMessages.labels(messageType || 'text', 'error').inc();
    firebaseOperations.labels('message_batch', 'error').inc();
    res.status(500).json({ 
      error: 'Failed to send message',
      code: 'MESSAGE_SEND_FAILED'
    });
  }
});

// Notification endpoints
app.post('/api/notifications/register', authenticate, async (req, res) => {
  const { fcmToken, platform, deviceId } = req.body;

  if (!fcmToken) {
    return res.status(400).json({ error: 'FCM token required' });
  }

  try {
    await db.collection('users').doc(req.userId).update({
      fcmToken,
      platform: platform || 'unknown',
      deviceId: deviceId || 'unknown',
      lastTokenUpdate: admin.firestore.FieldValue.serverTimestamp()
    });

    firebaseOperations.labels('fcm_register', 'success').inc();
    console.log(`🔔 FCM token registered for ${req.contactId}`);
    res.json({ success: true, message: 'FCM token registered successfully' });

  } catch (error) {
    console.error('❌ Error registering FCM token:', error);
    firebaseOperations.labels('fcm_register', 'error').inc();
    res.status(500).json({ error: 'Failed to register FCM token' });
  }
});

app.post('/api/notifications/send', authenticate, async (req, res) => {
  const { targetContactId, title, body, data } = req.body;

  if (!targetContactId || !title || !body) {
    return res.status(400).json({ error: 'targetContactId, title, and body are required' });
  }

  try {
    const targetUser = await findUserByContactId(targetContactId);
    if (!targetUser || !targetUser.data.fcmToken) {
      return res.status(404).json({ error: 'Target user not found or no FCM token' });
    }

    const notificationData = {
      title,
      body,
      data: {
        ...data,
        senderContactId: req.contactId,
        timestamp: new Date().toISOString()
      },
      token: targetUser.data.fcmToken
    };

    await notificationService.sendNotification(notificationData);
    notificationsSent.labels(targetUser.data.platform || 'unknown', 'success').inc();
    
    console.log(`🔔 Custom notification sent: ${req.contactId} → ${targetContactId}`);
    res.json({ success: true, message: 'Notification sent successfully' });

  } catch (error) {
    console.error('❌ Error sending notification:', error);
    notificationsSent.labels('unknown', 'error').inc();
    res.status(500).json({ error: 'Failed to send notification' });
  }
});

// Get user chats
app.get('/api/chats', authenticate, async (req, res) => {
  try {
    const chatsSnapshot = await db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .orderBy('lastMessageTime', 'desc')
      .get();

    const chats = [];
    chatsSnapshot.forEach(doc => {
      const chatData = doc.data();
      chats.push({
        contactId: chatData.contactId,
        displayName: chatData.displayName || chatData.contactId,
        photoURL: chatData.photoURL,
        lastMessage: chatData.lastMessage || '',
        lastMessageTime: chatData.lastMessageTime,
        unreadCount: chatData.unreadCount || 0,
        isOnline: chatData.isOnline || false
      });
    });

    firebaseOperations.labels('chats_fetch', 'success').inc();
    console.log(`📬 Retrieved ${chats.length} chats for ${req.contactId}`);
    res.json({ chats, count: chats.length });

  } catch (error) {
    console.error('❌ Get chats error:', error);
    firebaseOperations.labels('chats_fetch', 'error').inc();
    res.status(500).json({ 
      error: 'Failed to fetch chats',
      code: 'CHATS_FETCH_FAILED'
    });
  }
});

// Get messages for a specific chat
app.get('/api/chat/:contactId/messages', authenticate, async (req, res) => {
  const { contactId } = req.params;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);

  try {
    const messagesSnapshot = await db.collection('users')
      .doc(req.userId)
      .collection('chats')
      .doc(contactId)
      .collection('messages')
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();

    const messages = [];
    messagesSnapshot.forEach(doc => {
      const data = doc.data();
      messages.push({
        id: doc.id,
        ...data,
        timestamp: data.timestamp?.toDate()?.toISOString() || new Date().toISOString()
      });
    });

    // Reverse to get chronological order (oldest first)
    messages.reverse();

    firebaseOperations.labels('messages_fetch', 'success').inc();
    console.log(`📬 Retrieved ${messages.length} messages for ${req.contactId} ↔ ${contactId}`);
    res.json({ 
      messages, 
      count: messages.length,
      hasMore: messages.length === limit
    });

  } catch (error) {
    console.error('❌ Get messages error:', error);
    firebaseOperations.labels('messages_fetch', 'error').inc();
    res.status(500).json({ 
      error: 'Failed to fetch messages',
      code: 'MESSAGES_FETCH_FAILED'
    });
  }
});

// Mark messages as delivered
app.post('/api/chat/delivered/:messageId', authenticate, async (req, res) => {
  const { messageId } = req.params;

  try {
    await db.collection('messageStatus').doc(messageId).set({
      status: 'delivered',
      deliveredAt: admin.firestore.FieldValue.serverTimestamp(),
      deliveredBy: req.contactId
    }, { merge: true });

    firebaseOperations.labels('message_status', 'success').inc();
    console.log(`✅ Message ${messageId} marked as delivered by ${req.contactId}`);
    res.json({ status: 'delivered' });
  } catch (error) {
    console.error('❌ Mark delivered error:', error);
    firebaseOperations.labels('message_status', 'error').inc();
    res.status(500).json({ error: 'Failed to mark as delivered' });
  }
});

// Mark messages as read
app.post('/api/chat/read/:messageId', authenticate, async (req, res) => {
  const { messageId } = req.params;

  try {
    await db.collection('messageStatus').doc(messageId).set({
      status: 'read',
      readAt: admin.firestore.FieldValue.serverTimestamp(),
      readBy: req.contactId
    }, { merge: true });

    firebaseOperations.labels('message_status', 'success').inc();
    console.log(`👁️ Message ${messageId} marked as read by ${req.contactId}`);
    res.json({ status: 'read' });
  } catch (error) {
    console.error('❌ Mark read error:', error);
    firebaseOperations.labels('message_status', 'error').inc();
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

// Contact lookup
app.get('/api/contacts/lookup/:contactId', authenticate, async (req, res) => {
  const { contactId } = req.params;

  try {
    const user = await findUserByContactId(contactId);
    
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    const userData = user.data;
    const isOnline = [...activeConnections.values()]
      .some(conn => conn.contactId === contactId);

    res.json({
      contactId: userData.contactId,
      displayName: userData.displayName || contactId,
      photoURL: userData.photoURL,
      isOnline,
      lastSeen: userData.lastSeen
    });
  } catch (error) {
    console.error('❌ Lookup contact error:', error);
    res.status(500).json({ 
      error: 'Failed to lookup contact',
      code: 'CONTACT_LOOKUP_FAILED'
    });
  }
});

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log(`🔌 Socket connected: ${socket.id}`);
  activeWebSocketConnections.inc();

  socket.on('authenticate', async (data) => {
    try {
      const { token, contactId, deviceId } = data;
      
      if (!token || !contactId) {
        socket.emit('auth_error', { error: 'Token and contactId required' });
        return;
      }

      const decodedToken = await admin.auth().verifyIdToken(token);
      const userId = decodedToken.uid;

      // Disconnect any existing socket for this user
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

      // Store new connection
      activeConnections.set(userId, { 
        socketId: socket.id, 
        contactId,
        deviceId,
        lastActive: Date.now(),
        connectedAt: new Date().toISOString()
      });
      socketToUser.set(socket.id, userId);
      contactToUser.set(contactId, userId);

      // Update user online status
      await db.collection('users').doc(userId).update({
        isOnline: true,
        lastActive: admin.firestore.FieldValue.serverTimestamp()
      });
      
      socket.emit('authenticated', { success: true, contactId });
      socket.broadcast.emit('user_online', { contactId });
      
      console.log(`⚡ Socket authenticated: ${contactId} (${socket.id})`);

    } catch (error) {
      console.error('❌ Socket authentication error:', error);
      socket.emit('auth_error', { error: 'Authentication failed' });
      socket.disconnect(true);
    }
  });

  // Handle typing indicators
  socket.on('typing_start', (data) => {
    const userId = socketToUser.get(socket.id);
    if (userId && data.contactId) {
      const connection = activeConnections.get(userId);
      if (connection) {
        socket.broadcast.emit('typing_start', { 
          contactId: connection.contactId,
          targetContactId: data.contactId
        });
      }
    }
  });

  socket.on('typing_stop', (data) => {
    const userId = socketToUser.get(socket.id);
    if (userId && data.contactId) {
      const connection = activeConnections.get(userId);
      if (connection) {
        socket.broadcast.emit('typing_stop', { 
          contactId: connection.contactId,
          targetContactId: data.contactId
        });
      }
    }
  });

  // Handle message delivery confirmation
  socket.on('message_delivered', async (data) => {
    const { messageId } = data;
    if (messageId) {
      try {
        await db.collection('messageStatus').doc(messageId).set({
          status: 'delivered',
          deliveredAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        
        socket.broadcast.emit('message_status_updated', { 
          messageId, 
          status: 'delivered' 
        });
      } catch (error) {
        console.error('❌ Error updating message status:', error);
      }
    }
  });

  // Handle disconnect
  socket.on('disconnect', async (reason) => {
    const userId = socketToUser.get(socket.id);
    if (userId) {
      const connection = activeConnections.get(userId);
      if (connection) {
        try {
          await db.collection('users').doc(userId).update({
            isOnline: false,
            lastSeen: admin.firestore.FieldValue.serverTimestamp()
          });

          socket.broadcast.emit('user_offline', { contactId: connection.contactId });
          contactToUser.delete(connection.contactId);
        } catch (error) {
          console.error('❌ Error updating offline status:', error);
        }
      }
      
      activeConnections.delete(userId);
      socketToUser.delete(socket.id);
      activeWebSocketConnections.dec();
      
      console.log(`🔌 Socket disconnected: ${userId} (${socket.id}), reason: ${reason}`);
    }
  });

  // Handle ping-pong for connection health
  socket.on('ping', () => {
    socket.emit('pong', { timestamp: Date.now() });
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    code: 'INTERNAL_ERROR'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    code: 'ROUTE_NOT_FOUND',
    path: req.originalUrl
  });
});

// ✅ NEW: Self-ping function to prevent Render sleeping
setInterval(async () => {
  try {
    const response = await fetch(`http://${HOST}/api/health`);
    if (response.ok) {
      console.log('🏓 Self-ping successful');
    } else {
      console.warn('⚠️ Self-ping failed with status:', response.status);
    }
  } catch (error) {
    console.warn('⚠️ Self-ping error:', error.message);
  }
}, 6 * 60 * 1000); // Every 6 minutes

// Cleanup inactive connections every 5 minutes
setInterval(() => {
  const now = Date.now();
  const inactiveThreshold = 10 * 60 * 1000; // 10 minutes

  for (const [userId, connection] of activeConnections.entries()) {
    if (now - connection.lastActive > inactiveThreshold) {
      const socket = io.sockets.sockets.get(connection.socketId);
      if (socket) {
        socket.disconnect(true);
      }
      activeConnections.delete(userId);
      socketToUser.delete(connection.socketId);
      contactToUser.delete(connection.contactId);
      console.log(`🧹 Cleaned up inactive connection: ${connection.contactId}`);
    }
  }
}, 5 * 60 * 1000);

// ✅ NEW: Update WebSocket connections gauge every minute
setInterval(() => {
  activeWebSocketConnections.set(activeConnections.size);
}, 60 * 1000);

// Start server
server.listen(PORT, HOST, () => {
  console.log(`🚀 SecureLink Server running on http://${HOST}:${PORT}`);
  console.log(`📱 Environment: ${NODE_ENV}`);
  console.log(`🔔 Push notifications: enabled`);
  console.log(`⚡ WebSocket: enabled`);
  console.log(`🛡️ Security: enabled`);
  console.log(`📊 Prometheus metrics: enabled on /metrics`);
  console.log(`🏓 Self-ping: enabled (every 6 minutes)`);
});

// Graceful shutdown
const shutdown = async (signal) => {
  console.log(`\n${signal} received, shutting down gracefully...`);
  
  io.close(() => {
    console.log('📡 WebSocket server closed');
  });
  
  server.close(() => {
    console.log('🌐 HTTP server closed');
    process.exit(0);
  });
  
  setTimeout(() => {
    console.log('⚠️ Forced shutdown');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚫 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

export { io, activeConnections };

