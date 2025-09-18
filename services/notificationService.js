// services/notificationService.js - ENHANCED BACKEND NODE.JS VERSION
import { getMessaging } from 'firebase-admin/messaging';
import { FieldValue } from 'firebase-admin/firestore';
import { db } from '../firebaseAdmin.js';

class NotificationService {
  constructor() {
    this.invalidTokens = new Set();
    this.tokenValidationCache = new Map();
    this.rateLimitCache = new Map();
    this.retryQueue = [];
    this.metrics = {
      totalSent: 0,
      totalFailed: 0,
      totalInvalidTokens: 0,
      totalRateLimited: 0
    };
  }

  // ✅ Enhanced notification sending with better error handling
  async sendNotification(notificationData) {
    try {
      const { token, title, body, data = {}, priority = 'high' } = notificationData;
      
      // ✅ Enhanced token validation
      if (!this.isValidTokenFormat(token)) {
        console.error('❌ Invalid token format:', token?.substring(0, 20) + '...');
        await this.handleInvalidToken(token, 'invalid_format');
        this.metrics.totalInvalidTokens++;
        return { success: false, error: 'Invalid token format' };
      }

      // ✅ Check blacklisted tokens
      if (this.invalidTokens.has(token)) {
        console.log('🚫 Skipping notification to blacklisted token');
        return { success: false, error: 'Token previously marked as invalid' };
      }

      // ✅ Rate limiting check
      if (this.isRateLimited(token)) {
        console.warn('⚠️ Rate limiting active for token');
        this.metrics.totalRateLimited++;
        return { success: false, error: 'Rate limited' };
      }

      // ✅ Build message with enhanced configuration
      const message = {
        token: token,
        notification: {
          title: title,
          body: body,
        },
        data: {
          ...data,
          timestamp: new Date().toISOString(),
          messageId: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        },
        android: {
          priority: priority,
          notification: {
            sound: 'default',
            priority: priority,
            defaultSound: true,
            channelId: 'default',
            clickAction: 'FLUTTER_NOTIFICATION_CLICK',
          },
          data: {
            ...data,
            click_action: 'FLUTTER_NOTIFICATION_CLICK',
          },
        },
        apns: {
          headers: {
            'apns-priority': priority === 'high' ? '10' : '5',
          },
          payload: {
            aps: {
              alert: {
                title: title,
                body: body,
              },
              sound: 'default',
              badge: 1,
              'content-available': 1,
            },
            ...data,
          },
        },
        webpush: {
          headers: {
            Urgency: priority,
          },
          notification: {
            title: title,
            body: body,
            icon: data.icon || '/icon-192x192.png',
            badge: data.badge || '/badge-72x72.png',
            tag: data.tag || 'default',
          },
        },
      };

      console.log(`📤 Sending notification to token: ${token.substring(0, 20)}...`);
      
      // ✅ Send notification using Firebase Admin SDK
      const response = await getMessaging().send(message);
      
      console.log('✅ Notification sent successfully:', response);
      
      // ✅ Update cache and metrics
      this.tokenValidationCache.set(token, {
        isValid: true,
        lastUsed: Date.now(),
        successCount: (this.tokenValidationCache.get(token)?.successCount || 0) + 1
      });
      
      this.updateRateLimit(token, true);
      this.metrics.totalSent++;
      
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
      this.metrics.totalFailed++;
      
      return { 
        success: false, 
        error: error.message,
        errorCode: error.code || error.errorInfo?.code
      };
    }
  }

  // ✅ Enhanced token format validation
  isValidTokenFormat(token) {
    if (!token || typeof token !== 'string') {
      return false;
    }
    
    // Clean the token
    token = token.trim();
    
    // Expo push tokens
    if (token.startsWith('ExponentPushToken[')) {
      const expoTokenRegex = /^ExponentPushToken\[[a-zA-Z0-9_-]{22,}\]$/;
      return expoTokenRegex.test(token);
    }
    
    // Firebase FCM tokens (contain colons and are longer)
    if (token.includes(':')) {
      const fcmTokenRegex = /^[a-zA-Z0-9:_-]{140,}$/;
      return fcmTokenRegex.test(token) && token.length >= 140;
    }
    
    // APNs tokens (hexadecimal, 64 characters)
    if (/^[a-fA-F0-9]{64}$/.test(token)) {
      return true;
    }
    
    // General token validation (fallback)
    const generalTokenRegex = /^[a-zA-Z0-9_-]{100,200}$/;
    return generalTokenRegex.test(token);
  }

  // ✅ Enhanced rate limiting
  isRateLimited(token) {
    const now = Date.now();
    const rateData = this.rateLimitCache.get(token);
    
    if (!rateData) return false;
    
    // Allow 10 notifications per minute per token
    const windowStart = now - 60000; // 1 minute window
    const recentAttempts = rateData.attempts.filter(time => time > windowStart);
    
    // More strict rate limiting for failed tokens
    const recentFailures = rateData.failures || 0;
    const maxAttempts = recentFailures > 3 ? 5 : 10;
    
    return recentAttempts.length >= maxAttempts;
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
    
    // Reset failure count if successful
    if (success && rateData.failures > 0) {
      rateData.failures = Math.max(0, rateData.failures - 1);
    }
    
    this.rateLimitCache.set(token, rateData);
  }

  // ✅ Enhanced FCM error handling
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
        await this.handleRateExceeded(token, 60000);
        break;
        
      case 'messaging/device-message-rate-exceeded':
        console.warn('⚠️ Device message rate exceeded');
        await this.handleRateExceeded(token, 300000);
        break;
        
      case 'messaging/topics-message-rate-exceeded':
        console.warn('⚠️ Topics message rate exceeded');
        break;
        
      case 'messaging/internal-error':
      case 'messaging/server-unavailable':
      case 'messaging/timeout':
        console.warn('⚠️ Temporary error, adding to retry queue');
        this.addToRetryQueue({ 
          token, 
          error: errorCode,
          originalData: error.originalData 
        });
        break;
        
      case 'messaging/payload-too-large':
        console.error('❌ Payload too large:', errorCode);
        break;
        
      case 'messaging/invalid-data-payload-key':
        console.error('❌ Invalid data payload key:', errorCode);
        break;
        
      default:
        console.error('❌ Unknown FCM error:', errorCode, error.message);
        // Add unknown errors to retry queue for investigation
        this.addToRetryQueue({ 
          token, 
          error: errorCode || 'unknown_error',
          errorMessage: error.message 
        });
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

  // ✅ Clean invalid tokens from Firestore
  async cleanInvalidTokenFromDatabase(invalidToken, reason) {
    try {
      console.log(`🔍 Searching for invalid token in database...`);
      
      // Use Firebase Admin SDK methods
      const usersCollection = db.collection('users');
      const snapshot = await usersCollection.where('fcmToken', '==', invalidToken).get();
      
      if (snapshot.empty) {
        console.log('ℹ️ Invalid token not found in any user records');
        return;
      }
      
      // Use Admin SDK batch operations
      const batch = db.batch();
      let cleanedCount = 0;
      
      snapshot.forEach(doc => {
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

  // ✅ Handle rate exceeded errors with exponential backoff
  async handleRateExceeded(token, baseBackoffTime) {
    const rateData = this.rateLimitCache.get(token);
    const backoffMultiplier = rateData?.failures || 1;
    const backoffTime = Math.min(baseBackoffTime * backoffMultiplier, 600000); // Max 10 minutes
    
    console.log(`⏰ Setting backoff for ${token.substring(0, 20)}... for ${backoffTime}ms`);
    
    setTimeout(() => {
      this.rateLimitCache.delete(token);
    }, backoffTime);
  }

  // ✅ Add to retry queue with better metadata
  addToRetryQueue(item) {
    this.retryQueue.push({
      ...item,
      addedAt: Date.now(),
      retryCount: 0,
      id: `retry_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    });
  }

  // ✅ Enhanced retry queue processing
  async processRetryQueue() {
    const now = Date.now();
    const readyToRetry = this.retryQueue.filter(item => 
      now - item.addedAt > Math.pow(2, item.retryCount) * 1000 && // Exponential backoff
      item.retryCount < 3 // Max 3 retries
    );

    console.log(`🔄 Processing ${readyToRetry.length} items from retry queue`);

    for (const item of readyToRetry) {
      try {
        // Use original data if available
        const notificationData = item.originalData || {
          token: item.token,
          title: 'Retry Notification',
          body: 'Retrying failed notification'
        };
        
        const result = await this.sendNotification(notificationData);
        
        if (result.success) {
          // Remove from queue
          this.retryQueue = this.retryQueue.filter(qi => qi.id !== item.id);
          console.log(`✅ Retry successful for item ${item.id}`);
        } else {
          item.retryCount++;
          item.lastRetryAt = now;
        }
      } catch (error) {
        item.retryCount++;
        item.lastRetryAt = now;
        console.error(`❌ Retry failed for item ${item.id}:`, error);
      }
    }

    // Clean up old items that have exceeded max retries or are too old
    const before = this.retryQueue.length;
    this.retryQueue = this.retryQueue.filter(item => 
      now - item.addedAt < 3600000 && // Remove after 1 hour
      item.retryCount < 3
    );
    const cleaned = before - this.retryQueue.length;
    
    if (cleaned > 0) {
      console.log(`🧹 Cleaned ${cleaned} expired retry items`);
    }
  }

  // ✅ Enhanced batch notifications with better concurrency control
  async sendBatchNotifications(notifications, options = {}) {
    const { 
      batchSize = 10, 
      delayBetweenBatches = 100,
      maxConcurrency = 5 
    } = options;
    
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
    
    console.log(`📤 Sending batch of ${validNotifications.length} notifications`);
    
    // Process in batches with concurrency control
    for (let i = 0; i < validNotifications.length; i += batchSize) {
      const batch = validNotifications.slice(i, i + batchSize);
      
      // Limit concurrency within each batch
      const chunks = [];
      for (let j = 0; j < batch.length; j += maxConcurrency) {
        chunks.push(batch.slice(j, j + maxConcurrency));
      }
      
      for (const chunk of chunks) {
        const chunkPromises = chunk.map(notification => this.sendNotification(notification));
        const chunkResults = await Promise.allSettled(chunkPromises);
        
        chunkResults.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            results.push({ ...chunk[index], ...result.value });
          } else {
            results.push({
              ...chunk[index],
              success: false,
              error: result.reason.message || 'Unknown error'
            });
          }
        });
      }
      
      // Delay between batches to avoid overwhelming FCM
      if (i + batchSize < validNotifications.length) {
        await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
      }
    }
    
    console.log(`✅ Batch completed: ${results.filter(r => r.success).length} succeeded, ${results.filter(r => !r.success).length} failed`);
    
    return {
      results,
      summary: {
        total: notifications.length,
        valid: validNotifications.length,
        succeeded: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
        timestamp: new Date().toISOString()
      }
    };
  }

  // ✅ Enhanced token validation with dry run
  async validateToken(token, userId) {
    try {
      if (!this.isValidTokenFormat(token)) {
        return { isValid: false, reason: 'invalid_format' };
      }
      
      // Check cache first
      const cached = this.tokenValidationCache.get(token);
      if (cached && (Date.now() - cached.lastUsed) < 24 * 60 * 60 * 1000) {
        return { isValid: cached.isValid, reason: 'cached', lastUsed: cached.lastUsed };
      }
      
      // Test token with a dry run using Admin SDK
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
        messageId: response,
        timestamp: new Date().toISOString()
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

  // ✅ Enhanced periodic cleanup with metrics
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
        if (recentAttempts.length === 0 && data.failures === 0) {
          this.rateLimitCache.delete(token);
          cleanedRateLimit++;
        } else if (recentAttempts.length > 0) {
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
      
      return {
        validationCacheCleaned: cleanedValidation,
        rateLimitCacheCleaned: cleanedRateLimit,
        invalidTokensCleared: invalidTokensCleared,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      console.error('❌ Error during token cleanup:', error);
      return { error: error.message, timestamp: new Date().toISOString() };
    }
  }

  // ✅ Enhanced service status with more metrics
  getServiceStatus() {
    const now = Date.now();
    
    // Calculate healthy tokens
    const healthyTokensCount = Array.from(this.tokenValidationCache.values())
      .filter(data => data.isValid && (now - data.lastUsed) < 86400000).length;
    
    // Calculate average validation age
    const validations = Array.from(this.tokenValidationCache.values());
    const averageValidationAge = validations.length > 0 
      ? Math.round(validations.reduce((sum, data) => sum + (now - data.lastUsed), 0) / validations.length / 1000)
      : 0;
    
    return {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      caches: {
        invalidTokensCount: this.invalidTokens.size,
        validationCacheSize: this.tokenValidationCache.size,
        rateLimitCacheSize: this.rateLimitCache.size,
        healthyTokensCount: healthyTokensCount,
      },
      queues: {
        retryQueueSize: this.retryQueue.length,
        pendingRetries: this.retryQueue.filter(item => item.retryCount < 3).length
      },
      metrics: {
        ...this.metrics,
        successRate: this.metrics.totalSent + this.metrics.totalFailed > 0 
          ? ((this.metrics.totalSent / (this.metrics.totalSent + this.metrics.totalFailed)) * 100).toFixed(2) + '%'
          : '0%',
        averageValidationAge: averageValidationAge + 's',
      },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        memoryUsage: process.memoryUsage(),
        loadAverage: process.platform === 'linux' ? process.loadavg() : null,
      }
    };
  }

  // ✅ Health check with Firebase connectivity test
  async healthCheck() {
    try {
      // Test Firebase Admin connection
      await db.collection('_health').doc('notification_service').set({
        timestamp: FieldValue.serverTimestamp(),
        service: 'notification-service',
        status: 'healthy',
        version: '2.0.0'
      });
      
      // Test messaging service
      const testToken = 'test_token_invalid';
      try {
        await getMessaging().send({
          token: testToken,
          data: { test: 'health_check' }
        }, true); // dry run
      } catch (error) {
        // Expected to fail with invalid token, but confirms messaging service is working
        if (error.code !== 'messaging/invalid-registration-token') {
          throw error;
        }
      }
      
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        services: {
          firestore: 'connected',
          messaging: 'available',
          cache: 'operational',
        },
        ...this.getServiceStatus()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString(),
        services: {
          firestore: 'error',
          messaging: 'error',
          cache: 'unknown',
        }
      };
    }
  }

  // ✅ Reset metrics (useful for monitoring)
  resetMetrics() {
    this.metrics = {
      totalSent: 0,
      totalFailed: 0,
      totalInvalidTokens: 0,
      totalRateLimited: 0
    };
    console.log('📊 Metrics reset');
  }
}

// ✅ Export singleton instance
const notificationService = new NotificationService();

// ✅ Setup automatic cleanup every hour
setInterval(() => {
  notificationService.performTokenCleanup();
}, 60 * 60 * 1000);

// ✅ Setup retry queue processing every 5 minutes
setInterval(() => {
  notificationService.processRetryQueue();
}, 5 * 60 * 1000);

export default notificationService;

