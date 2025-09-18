// services/notificationService.js - BACKEND NODE.JS VERSION
import { getMessaging } from 'firebase-admin/messaging';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { db } from './firebaseAdmin.js';

class NotificationService {
  constructor() {
    this.invalidTokens = new Set();
    this.tokenValidationCache = new Map();
    this.rateLimitCache = new Map();
    this.retryQueue = [];
  }

  // ✅ Enhanced notification sending with token validation
  async sendNotification(notificationData) {
    try {
      const { token, title, body, data = {} } = notificationData;
      
      // ✅ Validate token format first
      if (!this.isValidTokenFormat(token)) {
        console.error('❌ Invalid token format:', token?.substring(0, 20) + '...');
        await this.handleInvalidToken(token, 'invalid_format');
        return { success: false, error: 'Invalid token format' };
      }

      // ✅ Check if token is in our invalid tokens cache
      if (this.invalidTokens.has(token)) {
        console.log('🚫 Skipping notification to known invalid token');
        return { success: false, error: 'Token previously marked as invalid' };
      }

      // ✅ Rate limiting check
      if (this.isRateLimited(token)) {
        console.warn('⚠️ Rate limiting active for token');
        return { success: false, error: 'Rate limited' };
      }

      const message = {
        token: token,
        notification: {
          title: title,
          body: body,
        },
        data: {
          ...data,
          timestamp: new Date().toISOString(),
        },
        android: {
          priority: 'high',
          notification: {
            sound: 'default',
            priority: 'high',
            defaultSound: true,
            channelId: 'default',
          },
        },
        apns: {
          payload: {
            aps: {
              alert: {
                title: title,
                body: body,
              },
              sound: 'default',
              badge: 1,
            },
          },
        },
      };

      console.log(`📤 Sending notification to token: ${token.substring(0, 20)}...`);
      
      // ✅ Send notification using Firebase Admin SDK
      const response = await getMessaging().send(message);
      
      console.log('✅ Notification sent successfully:', response);
      
      // ✅ Mark token as valid in cache
      this.tokenValidationCache.set(token, {
        isValid: true,
        lastUsed: Date.now(),
        successCount: (this.tokenValidationCache.get(token)?.successCount || 0) + 1
      });
      
      // Update rate limiting
      this.updateRateLimit(token, true);
      
      return { 
        success: true, 
        messageId: response,
        timestamp: new Date().toISOString() 
      };

    } catch (error) {
      console.error('❌ Error sending notification:', error);
      
      // ✅ Handle specific FCM errors
      await this.handleFCMError(error, notificationData.token);
      
      // Update rate limiting for failed attempts
      this.updateRateLimit(notificationData.token, false);
      
      return { 
        success: false, 
        error: error.message,
        errorCode: error.code || error.errorInfo?.code
      };
    }
  }

  // ✅ Validate FCM token format (enhanced for both FCM and Expo tokens)
  isValidTokenFormat(token) {
    if (!token || typeof token !== 'string') {
      return false;
    }
    
    // Clean the token
    token = token.trim();
    
    // Check for Expo push tokens
    if (token.startsWith('ExponentPushToken[')) {
      const expoTokenRegex = /^ExponentPushToken\[[a-zA-Z0-9_-]+\]$/;
      return expoTokenRegex.test(token);
    }
    
    // Check for regular FCM tokens
    if (token.includes(':')) {
      // FCM tokens typically contain colons and are longer
      const fcmTokenRegex = /^[a-zA-Z0-9:_-]{100,}$/;
      return fcmTokenRegex.test(token) && token.length >= 140;
    }
    
    // General token validation
    const generalTokenRegex = /^[a-zA-Z0-9_-]{140,200}$/;
    return generalTokenRegex.test(token);
  }

  // ✅ Rate limiting implementation
  isRateLimited(token) {
    const now = Date.now();
    const rateData = this.rateLimitCache.get(token);
    
    if (!rateData) return false;
    
    // Allow 10 notifications per minute per token
    const windowStart = now - 60000; // 1 minute window
    const recentAttempts = rateData.attempts.filter(time => time > windowStart);
    
    return recentAttempts.length >= 10;
  }

  // ✅ Update rate limiting data
  updateRateLimit(token, success) {
    const now = Date.now();
    const rateData = this.rateLimitCache.get(token) || { attempts: [], failures: 0 };
    
    rateData.attempts.push(now);
    if (!success) rateData.failures++;
    
    // Keep only last hour of attempts
    const oneHourAgo = now - 3600000;
    rateData.attempts = rateData.attempts.filter(time => time > oneHourAgo);
    
    this.rateLimitCache.set(token, rateData);
  }

  // ✅ Handle FCM-specific errors
  async handleFCMError(error, token) {
    const errorCode = error.code || error.errorInfo?.code;
    
    switch (errorCode) {
      case 'messaging/invalid-registration-token':
      case 'messaging/registration-token-not-registered':
      case 'messaging/invalid-argument':
        console.log(`🗑️ Marking token as invalid: ${errorCode}`);
        await this.handleInvalidToken(token, errorCode);
        break;
        
      case 'messaging/message-rate-exceeded':
        console.warn('⚠️ Message rate exceeded, implementing backoff');
        await this.handleRateExceeded(token);
        break;
        
      case 'messaging/device-message-rate-exceeded':
        console.warn('⚠️ Device message rate exceeded');
        await this.handleDeviceRateExceeded(token);
        break;
        
      case 'messaging/topics-message-rate-exceeded':
        console.warn('⚠️ Topics message rate exceeded');
        break;
        
      case 'messaging/internal-error':
      case 'messaging/server-unavailable':
        console.warn('⚠️ Temporary error, adding to retry queue');
        this.addToRetryQueue({ token, error: errorCode });
        break;
        
      default:
        console.error('❌ Unknown FCM error:', errorCode, error.message);
    }
  }

  // ✅ Handle invalid tokens using Firebase Admin SDK
  async handleInvalidToken(token, reason) {
    try {
      // Add to invalid tokens cache
      this.invalidTokens.add(token);
      
      console.log(`🗑️ Handling invalid token: ${reason}`);
      
      // ✅ Clean token from Firestore using Admin SDK
      await this.cleanInvalidTokenFromDatabase(token, reason);
      
    } catch (error) {
      console.error('❌ Error handling invalid token:', error);
    }
  }

  // ✅ Clean invalid tokens from Firestore using Firebase Admin SDK
  async cleanInvalidTokenFromDatabase(invalidToken, reason) {
    try {
      console.log(`🔍 Searching for invalid token in database...`);
      
      // ✅ Use Firebase Admin SDK methods
      const usersCollection = db.collection('users');
      const snapshot = await usersCollection.where('fcmToken', '==', invalidToken).get();
      
      if (snapshot.empty) {
        console.log('ℹ️ Invalid token not found in any user records');
        return;
      }
      
      // ✅ Use Admin SDK batch operations
      const batch = db.batch();
      let cleanedCount = 0;
      
      snapshot.forEach(doc => {
        // ✅ Use FieldValue.delete() from Admin SDK
        batch.update(doc.ref, {
          fcmToken: FieldValue.delete(),
          fcmTokenUpdatedAt: FieldValue.serverTimestamp(),
          tokenInvalidatedAt: FieldValue.serverTimestamp(),
          tokenInvalidationReason: reason,
          lastNotificationAttempt: FieldValue.serverTimestamp()
        });
        cleanedCount++;
      });
      
      await batch.commit();
      console.log(`✅ Cleaned invalid token from ${cleanedCount} user(s)`);
      
    } catch (error) {
      console.error('❌ Error cleaning invalid token from database:', error);
    }
  }

  // ✅ Handle rate exceeded errors
  async handleRateExceeded(token) {
    const backoffTime = 60000; // 1 minute backoff
    setTimeout(() => {
      this.rateLimitCache.delete(token);
    }, backoffTime);
  }

  // ✅ Handle device rate exceeded
  async handleDeviceRateExceeded(token) {
    const backoffTime = 300000; // 5 minute backoff
    setTimeout(() => {
      this.rateLimitCache.delete(token);
    }, backoffTime);
  }

  // ✅ Add to retry queue
  addToRetryQueue(item) {
    this.retryQueue.push({
      ...item,
      addedAt: Date.now(),
      retryCount: 0
    });
  }

  // ✅ Process retry queue
  async processRetryQueue() {
    const now = Date.now();
    const readyToRetry = this.retryQueue.filter(item => 
      now - item.addedAt > Math.pow(2, item.retryCount) * 1000 && // Exponential backoff
      item.retryCount < 3 // Max 3 retries
    );

    for (const item of readyToRetry) {
      try {
        const result = await this.sendNotification({
          token: item.token,
          title: 'Retry Notification',
          body: 'Retrying failed notification'
        });
        
        if (result.success) {
          // Remove from queue
          this.retryQueue = this.retryQueue.filter(qi => qi !== item);
        } else {
          item.retryCount++;
        }
      } catch (error) {
        item.retryCount++;
        console.error('❌ Retry failed:', error);
      }
    }

    // Clean up old items
    this.retryQueue = this.retryQueue.filter(item => 
      now - item.addedAt < 3600000 && // Remove after 1 hour
      item.retryCount < 3
    );
  }

  // ✅ Batch send notifications with enhanced filtering
  async sendBatchNotifications(notifications) {
    const results = [];
    const validNotifications = [];
    
    // Filter and validate notifications
    for (const notification of notifications) {
      if (this.isValidTokenFormat(notification.token) && 
          !this.invalidTokens.has(notification.token) &&
          !this.isRateLimited(notification.token)) {
        validNotifications.push(notification);
      } else {
        results.push({
          ...notification,
          success: false,
          error: 'Invalid, blacklisted, or rate-limited token',
          timestamp: new Date().toISOString()
        });
      }
    }
    
    // Send to valid tokens with concurrency control
    const BATCH_SIZE = 10; // Process 10 notifications at a time
    for (let i = 0; i < validNotifications.length; i += BATCH_SIZE) {
      const batch = validNotifications.slice(i, i + BATCH_SIZE);
      const batchPromises = batch.map(notification => this.sendNotification(notification));
      const batchResults = await Promise.allSettled(batchPromises);
      
      batchResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.push({ ...batch[index], ...result.value });
        } else {
          results.push({
            ...batch[index],
            success: false,
            error: result.reason.message || 'Unknown error'
          });
        }
      });
      
      // Small delay between batches to avoid overwhelming FCM
      if (i + BATCH_SIZE < validNotifications.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    return results;
  }

  // ✅ Validate token with dry run
  async validateToken(token, userId) {
    try {
      if (!this.isValidTokenFormat(token)) {
        return { isValid: false, reason: 'invalid_format' };
      }
      
      // Check cache first
      const cached = this.tokenValidationCache.get(token);
      if (cached && (Date.now() - cached.lastUsed) < 24 * 60 * 60 * 1000) {
        return { isValid: cached.isValid, reason: 'cached' };
      }
      
      // ✅ Test token with a dry run using Admin SDK
      const testMessage = {
        token: token,
        data: { 
          test: 'validation',
          timestamp: new Date().toISOString()
        }
      };
      
      // Use dry run to validate without sending
      const response = await getMessaging().send(testMessage, true); // true = dry run
      
      // If we reach here, token is valid
      this.tokenValidationCache.set(token, {
        isValid: true,
        lastUsed: Date.now(),
        validatedAt: Date.now()
      });
      
      return { 
        isValid: true, 
        reason: 'validated',
        messageId: response 
      };
      
    } catch (error) {
      const errorCode = error.code || error.errorInfo?.code;
      
      if (errorCode === 'messaging/invalid-registration-token' ||
          errorCode === 'messaging/registration-token-not-registered') {
        
        await this.handleInvalidToken(token, errorCode);
        return { isValid: false, reason: errorCode };
      }
      
      // For other errors, assume token might be valid but there's a temporary issue
      return { isValid: false, reason: 'validation_error', error: error.message };
    }
  }

  // ✅ Enhanced periodic cleanup
  async performTokenCleanup() {
    try {
      console.log('🧹 Starting comprehensive token cleanup...');
      
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);
      
      // Clear old entries from validation cache
      let cleanedValidation = 0;
      for (const [token, data] of this.tokenValidationCache.entries()) {
        if (data.lastUsed < oneDayAgo) {
          this.tokenValidationCache.delete(token);
          cleanedValidation++;
        }
      }
      
      // Clear old entries from rate limit cache
      let cleanedRateLimit = 0;
      for (const [token, data] of this.rateLimitCache.entries()) {
        const recentAttempts = data.attempts.filter(time => time > oneDayAgo);
        if (recentAttempts.length === 0) {
          this.rateLimitCache.delete(token);
          cleanedRateLimit++;
        } else {
          // Update with filtered attempts
          this.rateLimitCache.set(token, {
            ...data,
            attempts: recentAttempts
          });
        }
      }
      
      // Clear invalid tokens cache (allow retry after 24 hours)
      const invalidTokensCleared = this.invalidTokens.size;
      this.invalidTokens.clear();
      
      // Process retry queue
      await this.processRetryQueue();
      
      console.log(`✅ Cleanup completed: ${cleanedValidation} validation cache, ${cleanedRateLimit} rate limit cache, ${invalidTokensCleared} invalid tokens cleared`);
      
    } catch (error) {
      console.error('❌ Error during token cleanup:', error);
    }
  }

  // ✅ Enhanced service status
  getServiceStatus() {
    const now = Date.now();
    
    return {
      timestamp: new Date().toISOString(),
      caches: {
        invalidTokensCount: this.invalidTokens.size,
        validationCacheSize: this.tokenValidationCache.size,
        rateLimitCacheSize: this.rateLimitCache.size,
      },
      queues: {
        retryQueueSize: this.retryQueue.length,
        pendingRetries: this.retryQueue.filter(item => item.retryCount < 3).length
      },
      performance: {
        averageValidationAge: this.getAverageValidationAge(),
        healthyTokensCount: Array.from(this.tokenValidationCache.values())
          .filter(data => data.isValid && (now - data.lastUsed) < 86400000).length
      },
      system: {
        nodeVersion: process.version,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
      }
    };
  }

  // ✅ Get average validation age
  getAverageValidationAge() {
    const now = Date.now();
    const validations = Array.from(this.tokenValidationCache.values());
    
    if (validations.length === 0) return 0;
    
    const totalAge = validations.reduce((sum, data) => sum + (now - data.lastUsed), 0);
    return Math.round(totalAge / validations.length / 1000); // Return in seconds
  }

  // ✅ Health check
  async healthCheck() {
    try {
      // Test Firebase Admin connection
      const testDoc = await db.collection('_health').doc('test').set({
        timestamp: FieldValue.serverTimestamp(),
        service: 'notification-service'
      });
      
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        firestore: 'connected',
        messaging: 'available',
        ...this.getServiceStatus()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}

export default new NotificationService();
