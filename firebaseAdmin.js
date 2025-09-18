// services/firebaseAdmin.js
import admin from 'firebase-admin';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

// Load environment variables
dotenv.config();

// ✅ Enhanced logging with better security (don't log sensitive data)
console.log('🔥 Initializing Firebase Admin SDK...');
console.log('📋 Project ID:', process.env.FIREBASE_PROJECT_ID);
console.log('📧 Client Email:', process.env.FIREBASE_CLIENT_EMAIL?.substring(0, 20) + '...');
console.log('🔑 Private Key Available:', !!process.env.FIREBASE_PRIVATE_KEY);
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

// ✅ Enhanced Firebase Admin initialization with multiple methods
let app;

if (!admin.apps.length) {
  try {
    // Method 1: Use service account key file if available
    const serviceAccountPath = path.join(process.cwd(), 'serviceAccountKey.json');
    
    if (fs.existsSync(serviceAccountPath)) {
      console.log('🔐 Using service account key file');
      const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));
      
      app = admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id,
      });
      
    } else if (process.env.FIREBASE_PROJECT_ID && 
               process.env.FIREBASE_CLIENT_EMAIL && 
               process.env.FIREBASE_PRIVATE_KEY) {
      
      console.log('🔐 Using environment variables');
      
      // ✅ Enhanced private key processing
      let privateKey = process.env.FIREBASE_PRIVATE_KEY;
      
      // Handle different private key formats
      if (privateKey.includes('\\n')) {
        privateKey = privateKey.replace(/\\n/g, '\n');
      }
      
      // Ensure proper private key format
      if (!privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
        throw new Error('Invalid private key format. Make sure it includes the full key with headers.');
      }
      
      const serviceAccount = {
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: privateKey,
      };
      
      app = admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: process.env.FIREBASE_PROJECT_ID,
        // ✅ Optional: Add other configurations
        databaseURL: process.env.FIREBASE_DATABASE_URL,
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
      });
      
    } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      console.log('🔐 Using Google Application Credentials');
      
      app = admin.initializeApp({
        credential: admin.credential.applicationDefault(),
        projectId: process.env.FIREBASE_PROJECT_ID,
      });
      
    } else {
      console.log('🔐 Using default credentials (for deployed environments)');
      
      // This works in Google Cloud environments (Cloud Functions, Cloud Run, etc.)
      app = admin.initializeApp();
    }
    
    console.log('✅ Firebase Admin SDK initialized successfully');
    
  } catch (error) {
    console.error('❌ Firebase Admin initialization error:', error.message);
    
    // Provide helpful error messages
    if (error.message.includes('private key')) {
      console.error('💡 Tip: Make sure your FIREBASE_PRIVATE_KEY includes the full private key with headers');
      console.error('💡 Format: "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"');
    }
    
    if (error.message.includes('project')) {
      console.error('💡 Tip: Make sure FIREBASE_PROJECT_ID is set correctly');
    }
    
    if (error.message.includes('client_email')) {
      console.error('💡 Tip: Make sure FIREBASE_CLIENT_EMAIL is set correctly');
    }
    
    process.exit(1); // Exit if Firebase can't initialize
  }
} else {
  console.log('🔄 Using existing Firebase Admin app');
  app = admin.apps[0];
}

// ✅ Initialize and export all Firebase services
const db = admin.firestore();
const auth = admin.auth();
const messaging = admin.messaging();
const storage = admin.storage();

// ✅ Configure Firestore settings for better performance
db.settings({
  ignoreUndefinedProperties: true,
  timestampsInSnapshots: true,
});

// ✅ Export everything you might need
export { 
  admin, 
  app,
  db, 
  auth, 
  messaging, 
  storage 
};

// ✅ Export default for compatibility
export default app;

// ✅ Helper functions for common operations
export const FieldValue = admin.firestore.FieldValue;
export const Timestamp = admin.firestore.Timestamp;

// ✅ Utility functions
export const getServerTimestamp = () => admin.firestore.FieldValue.serverTimestamp();
export const deleteField = () => admin.firestore.FieldValue.delete();
export const increment = (value = 1) => admin.firestore.FieldValue.increment(value);
export const arrayUnion = (...elements) => admin.firestore.FieldValue.arrayUnion(...elements);
export const arrayRemove = (...elements) => admin.firestore.FieldValue.arrayRemove(...elements);

// ✅ Connection test function
export const testFirebaseConnection = async () => {
  try {
    // Test Firestore connection
    const testDoc = await db.collection('_connection_test').doc('test').set({
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'connected',
      environment: process.env.NODE_ENV || 'development',
      projectId: app.options.projectId
    });
    
    console.log('✅ Firebase connection test successful');
    
    // Clean up test document
    await db.collection('_connection_test').doc('test').delete();
    
    return {
      success: true,
      projectId: app.options.projectId,
      timestamp: new Date().toISOString()
    };
    
  } catch (error) {
    console.error('❌ Firebase connection test failed:', error);
    return {
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
};

// ✅ Enhanced error handler for Firebase operations
export const handleFirebaseError = (error, operation = 'Firebase operation') => {
  console.error(`❌ ${operation} failed:`, error);
  
  // Map common Firebase errors to user-friendly messages
  const errorMap = {
    'permission-denied': 'Permission denied. Check your security rules.',
    'not-found': 'The requested resource was not found.',
    'already-exists': 'The resource already exists.',
    'failed-precondition': 'Operation failed due to precondition.',
    'aborted': 'Operation was aborted.',
    'out-of-range': 'Value is out of valid range.',
    'unimplemented': 'Operation is not implemented.',
    'internal': 'Internal server error occurred.',
    'unavailable': 'Service is temporarily unavailable.',
    'data-loss': 'Unrecoverable data loss occurred.',
    'unauthenticated': 'Request lacks valid authentication credentials.'
  };
  
  const friendlyMessage = errorMap[error.code] || error.message || 'An unknown error occurred';
  
  return {
    code: error.code,
    message: friendlyMessage,
    originalMessage: error.message,
    timestamp: new Date().toISOString()
  };
};

// ✅ Health check function
export const getFirebaseStatus = () => {
  return {
    initialized: !!app,
    projectId: app?.options?.projectId,
    services: {
      firestore: !!db,
      auth: !!auth,
      messaging: !!messaging,
      storage: !!storage,
    },
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  };
};

// ✅ Graceful shutdown handler
export const shutdownFirebase = async () => {
  try {
    console.log('🔄 Shutting down Firebase Admin SDK...');
    
    if (app) {
      await app.delete();
      console.log('✅ Firebase Admin SDK shutdown complete');
    }
    
  } catch (error) {
    console.error('❌ Error during Firebase shutdown:', error);
  }
};

// ✅ Process event handlers for graceful shutdown
process.on('SIGINT', async () => {
  console.log('📡 Received SIGINT, shutting down gracefully...');
  await shutdownFirebase();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('📡 Received SIGTERM, shutting down gracefully...');
  await shutdownFirebase();
  process.exit(0);
});

// ✅ Log successful initialization
console.log('🎉 Firebase Admin services ready:', {
  projectId: app.options.projectId,
  firestore: '✅',
  auth: '✅', 
  messaging: '✅',
  storage: '✅'
});
