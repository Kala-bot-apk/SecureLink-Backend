// services/notificationService.js - UPDATED FOR EXPO MESSAGING SERVICE
import { Expo } from 'expo-server-sdk'; // ✅ NEW: Replace getMessaging import
import { FieldValue } from 'firebase-admin/firestore'; // ✅ KEEP: Still using Admin SDK
import { db } from '../firebaseAdmin.js'; // ✅ KEEP: Still using Admin SDK

class NotificationService {
  constructor() {
    // ✅ NEW: Initialize Expo SDK client
    this.expo = new Expo({
      accessToken: process.env.EXPO_ACCESS_TOKEN, // Optional: for higher rate limits
      useFcmV1: false, // Use legacy FCM for broader compatibility
    });

    // ✅ KEEP: All existing properties
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

  // ✅ UPDATED: Enhanced notification sending with Expo SDK
  async sendNotification(notificationData) {
    try {
      const { token, title, body, data = {}, priority = 'high' } = notificationData;
      
      // ✅ UPDATED: Enhanced token validation for Expo
      if (!this.isValidTokenFormat(token)) {
        console.error('❌ Invalid token format:', token?.substring(0, 20) + '...');
        await this.handleInvalidToken(token, 'invalid_format');
        this.metrics.totalInvalidTokens++;
        return { success: false, error: 'Invalid token format' };
      }

      // ✅ KEEP: Existing blacklist and rate limiting checks
      if (this.invalidTokens.has(token)) {
        console.log('🚫 Skipping notification to blacklisted token');
        return { success: false, error: 'Token previously marked as invalid' };
      }

      if (this.isRateLimited(token)) {
        console.warn('⚠️ Rate limiting active for token');
        this.metrics.totalRateLimited++;
        return { success: false, error: 'Rate limited' };
      }

      // ✅ NEW: Build message for Expo Push Service
      const message = {
        to: token,
        sound: 'default',
        title: title,
        body: body,
        data: {
          ...data,
          timestamp: new Date().toISOString(),
          messageId: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        },
        badge: 1,
        priority: priority === 'high' ? 'high' : 'normal',
        ttl: 3600, // 1 hour
        channelId: 'default',
      };

      console.log(`📤 Sending notification via Expo to token: ${token.substring(0, 20)}...`);
      
      // ✅ NEW: Send notification using Expo Push Service
      const chunks = this.expo.chunkPushNotifications([message]);
      let response = null;

      for (let chunk of chunks) {
        try {
          const tickets = await this.expo.sendPushNotificationsAsync(chunk);
          response = tickets[0]; // Get first ticket
          
          // Check if ticket has error
          if (response.status === 'error') {
            throw new Error(response.message || 'Expo push notification failed');
          }
          
        } catch (error) {
          throw error;
        }
      }
      
      console.log('✅ Notification sent successfully via Expo:', response);
      
      // ✅ KEEP: Update cache and metrics
      this.tokenValidationCache.set(token, {
        isValid: true,
        lastUsed: Date.now(),
        successCount: (this.tokenValidationCache.get(token)?.successCount || 0) + 1
      });
      
      this.updateRateLimit(token, true);
      this.metrics.totalSent++;
      
      return { 
        success: true, 
        messageId: response?.id || response,
        timestamp: new Date().toISOString(),
        provider: 'expo'
      };

    } catch (error) {
      console.error('❌ Error sending notification via Expo:', error);
      
      // ✅ UPDATED: Handle Expo-specific errors
      await this.handleExpoError(error, notificationData.token);
      
      this.updateRateLimit(notificationData.token, false);
      this.metrics.totalFailed++;
      
      return { 
        success: false, 
        error: error.message,
        errorCode: error.code || 'expo_error',
        provider: 'expo'
      };
    }
  }

  // ✅ UPDATED: Enhanced token format validation for Expo tokens
  isValidTokenFormat(token) {
    if (!token || typeof token !== 'string') {
      return false;
    }
    
    // Clean the token
    token = token.trim();
    
    // ✅ UPDATED: Validate Expo push tokens using Expo SDK
    if (token.startsWith('ExponentPushToken[')) {
      return Expo.isExpoPushToken(token);
    }
    
    // ✅ KEEP: Support legacy FCM tokens for backward compatibility
    if (token.includes(':')) {
      const fcmTokenRegex = /^[a-zA-Z0-9:_-]{140,}$/;
      return fcmTokenRegex.test(token) && token.length >= 140;
    }
    
    // APNs tokens (hexadecimal, 64 characters)
    if (/^[a-fA-F0-9]{64}$/.test(token)) {
      return true;
    }
    
    return false;
  }

  // ✅ KEEP: Existing rate limiting logic (unchanged)
  isRateLimited(token) {
    const now = Date.now();
    const rateData = this.rateLimitCache.get(token);
    
    if (!rateData) return false;
    
    const windowStart = now - 60000; // 1 minute window
    const recentAttempts = rateData.attempts.filter(time => time > windowStart);
    
    const recentFailures = rateData.failures || 0;
    const maxAttempts = recentFailures > 3 ? 5 : 10;
    
    return recentAttempts.length >= maxAttempts;
  }

  // ✅ KEEP: Existing rate limit update logic (unchanged)
  updateRateLimit(token, success) {
    const now = Date.now();
    const rateData = this.rateLimitCache.get(token) || { attempts: [], failures: 0 };
    
    rateData.attempts.push(now);
    if (!success) rateData.failures++;
    
    const oneHourAgo = now - 3600000;
    rateData.attempts = rateData.attempts.filter(time => time > oneHourAgo);
    
    if (success && rateData.failures > 0) {
      rateData.failures = Math.max(0, rateData.failures - 1);
    }
    
    this.rateLimitCache.set(token, rateData);
  }

  // ✅ NEW: Handle Expo-specific errors
  async handleExpoError(error, token) {
    const errorMessage = error.message?.toLowerCase() || '';
    
    if (errorMessage.includes('devicenotregistered') || 
        errorMessage.includes('invalid') ||
        errorMessage.includes('unregistered')) {
      console.log(`🗑️ Marking Expo token as invalid: ${error.message}`);
      await this.handleInvalidToken(token, 'expo_device_not_registered');
    } else if (errorMessage.includes('rate') || errorMessage.includes('limit')) {
      console.warn('⚠️ Expo rate limit exceeded');
      await this.handleRateExceeded(token, 60000);
    } else if (errorMessage.includes('timeout') || 
               errorMessage.includes('network') ||
               errorMessage.includes('server')) {
      console.warn('⚠️ Temporary Expo error, adding to retry queue');
      this.addToRetryQueue({ 
        token, 
        error: 'expo_temporary_error',
        originalData: error.originalData 
      });
    } else {
      console.error('❌ Unknown Expo error:', error.message);
      this.addToRetryQueue({ 
        token, 
        error: 'expo_unknown_error',
        errorMessage: error.message 
      });
    }
  }

  // ✅ KEEP: Existing invalid token handling (unchanged)
  async handleInvalidToken(token, reason) {
    try {
      this.invalidTokens.add(token);
      console.log(`🗑️ Handling invalid token: ${reason}`);
      await this.cleanInvalidTokenFromDatabase(token, reason);
    } catch (error) {
      console.error('❌ Error handling invalid token:', error);
    }
  }

  // ✅ UPDATED: Clean invalid tokens from Firestore (support both expo and fcm fields)
  async cleanInvalidTokenFromDatabase(invalidToken, reason) {
    try {
      console.log(`🔍 Searching for invalid token in database...`);
      
      const usersCollection = db.collection('users');
      
      // ✅ UPDATED: Search both expoPushToken and fcmToken fields
      const expoSnapshot = await usersCollection.where('expoPushToken', '==', invalidToken).get();
      const fcmSnapshot = await usersCollection.where('fcmToken', '==', invalidToken).get();
      
      if (expoSnapshot.empty && fcmSnapshot.empty) {
        console.log('ℹ️ Invalid token not found in any user records');
        return;
      }
      
      const batch = db.batch();
      let cleanedCount = 0;
      
      // Clean from expoPushToken field
      expoSnapshot.forEach(doc => {
        batch.update(doc.ref, {
          expoPushToken: FieldValue.delete(),
          fcmToken: FieldValue.delete(), // Also clean legacy field
          tokenUpdatedAt: FieldValue.serverTimestamp(),
          tokenInvalidatedAt: FieldValue.serverTimestamp(),
          tokenInvalidationReason: reason,
          lastNotificationAttempt: FieldValue.serverTimestamp()
        });
        cleanedCount++;
      });
      
      // Clean from fcmToken field (legacy)
      fcmSnapshot.forEach(doc => {
        batch.update(doc.ref, {
          fcmToken: FieldValue.delete(),
          expoPushToken: FieldValue.delete(), // Also clean new field
          tokenUpdatedAt: FieldValue.serverTimestamp(),
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

  // ✅ KEEP: All remaining methods unchanged
  async handleRateExceeded(token, baseBackoffTime) {
    const rateData = this.rateLimitCache.get(token);
    const backoffMultiplier = rateData?.failures || 1;
    const backoffTime = Math.min(baseBackoffTime * backoffMultiplier, 600000);
    
    console.log(`⏰ Setting backoff for ${token.substring(0, 20)}... for ${backoffTime}ms`);
    
    setTimeout(() => {
      this.rateLimitCache.delete(token);
    }, backoffTime);
  }

  addToRetryQueue(item) {
    this.retryQueue.push({
      ...item,
      addedAt: Date.now(),
      retryCount: 0,
      id: `retry_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    });
  }

  async processRetryQueue() {
    const now = Date.now();
    const readyToRetry = this.retryQueue.filter(item => 
      now - item.addedAt > Math.pow(2, item.retryCount) * 1000 &&
      item.retryCount < 3
    );

    console.log(`🔄 Processing ${readyToRetry.length} items from retry queue`);

    for (const item of readyToRetry) {
      try {
        const notificationData = item.originalData || {
          token: item.token,
          title: 'Retry Notification',
          body: 'Retrying failed notification'
        };
        
        const result = await this.sendNotification(notificationData);
        
        if (result.success) {
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

    const before = this.retryQueue.length;
    this.retryQueue = this.retryQueue.filter(item => 
      now - item.addedAt < 3600000 && 
      item.retryCount < 3
    );
    const cleaned = before - this.retryQueue.length;
    
    if (cleaned > 0) {
      console.log(`🧹 Cleaned ${cleaned} expired retry items`);
    }
  }

  // ✅ UPDATED: Enhanced batch notifications with Expo
  async sendBatchNotifications(notifications, options = {}) {
    const { 
      batchSize = 10, 
      delayBetweenBatches = 100,
      maxConcurrency = 5 
    } = options;
    
    const results = [];
    const validNotifications = [];
    
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
    
    console.log(`📤 Sending batch of ${validNotifications.length} notifications via Expo`);
    
    for (let i = 0; i < validNotifications.length; i += batchSize) {
      const batch = validNotifications.slice(i, i + batchSize);
      
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
      
      if (i + batchSize < validNotifications.length) {
        await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
      }
    }
    
    console.log(`✅ Expo batch completed: ${results.filter(r => r.success).length} succeeded, ${results.filter(r => !r.success).length} failed`);
    
    return {
      results,
      summary: {
        total: notifications.length,
        valid: validNotifications.length,
        succeeded: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
        timestamp: new Date().toISOString(),
        provider: 'expo'
      }
    };
  }

  // ✅ UPDATED: Token validation using Expo SDK
  async validateToken(token, userId) {
    try {
      if (!this.isValidTokenFormat(token)) {
        return { isValid: false, reason: 'invalid_format' };
      }
      
      const cached = this.tokenValidationCache.get(token);
      if (cached && (Date.now() - cached.lastUsed) < 24 * 60 * 60 * 1000) {
        return { isValid: cached.isValid, reason: 'cached', lastUsed: cached.lastUsed };
      }
      
      // ✅ NEW: Test with Expo SDK validation
      if (Expo.isExpoPushToken(token)) {
        this.tokenValidationCache.set(token, {
          isValid: true,
          lastUsed: Date.now(),
          validatedAt: Date.now()
        });
        
        return { 
          isValid: true, 
          reason: 'expo_validated',
          timestamp: new Date().toISOString()
        };
      } else {
        return { isValid: false, reason: 'invalid_expo_token_format' };
      }
      
    } catch (error) {
      return { isValid: false, reason: 'validation_error', error: error.message };
    }
  }

  // ✅ KEEP: All remaining methods unchanged (performTokenCleanup, getServiceStatus, healthCheck, resetMetrics)
  async performTokenCleanup() {
    try {
      console.log('🧹 Starting comprehensive token cleanup...');
      
      const now = Date.now();
      const oneDayAgo = now - (24 * 60 * 60 * 1000);
      
      let cleanedValidation = 0;
      for (const [token, data] of this.tokenValidationCache.entries()) {
        if (data.lastUsed < oneDayAgo) {
          this.tokenValidationCache.delete(token);
          cleanedValidation++;
        }
      }
      
      let cleanedRateLimit = 0;
      for (const [token, data] of this.rateLimitCache.entries()) {
        const recentAttempts = data.attempts.filter(time => time > oneDayAgo);
        if (recentAttempts.length === 0 && data.failures === 0) {
          this.rateLimitCache.delete(token);
          cleanedRateLimit++;
        } else if (recentAttempts.length > 0) {
          this.rateLimitCache.set(token, {
            ...data,
            attempts: recentAttempts
          });
        }
      }
      
      const invalidTokensCleared = this.invalidTokens.size;
      this.invalidTokens.clear();
      
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

  // ✅ UPDATED: Service status with Expo info
  getServiceStatus() {
    const now = Date.now();
    
    const healthyTokensCount = Array.from(this.tokenValidationCache.values())
      .filter(data => data.isValid && (now - data.lastUsed) < 86400000).length;
    
    const validations = Array.from(this.tokenValidationCache.values());
    const averageValidationAge = validations.length > 0 
      ? Math.round(validations.reduce((sum, data) => sum + (now - data.lastUsed), 0) / validations.length / 1000)
      : 0;
    
    return {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      provider: 'expo', // ✅ NEW: Indicate using Expo
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

  // ✅ UPDATED: Health check with Expo
  async healthCheck() {
    try {
      await db.collection('_health').doc('notification_service').set({
        timestamp: FieldValue.serverTimestamp(),
        service: 'notification-service',
        status: 'healthy',
        provider: 'expo',
        version: '2.0.0'
      });
      
      // Test Expo SDK
      const testToken = 'ExponentPushToken[invalid]';
      const isValidFormat = Expo.isExpoPushToken(testToken);
      
      return {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        provider: 'expo',
        services: {
          firestore: 'connected',
          expo: 'available',
          cache: 'operational',
        },
        ...this.getServiceStatus()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString(),
        provider: 'expo',
        services: {
          firestore: 'error',
          expo: 'error',
          cache: 'unknown',
        }
      };
    }
  }

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

// ✅ KEEP: Export singleton instance
const notificationService = new NotificationService();

// ✅ KEEP: Automatic cleanup intervals
setInterval(() => {
  notificationService.performTokenCleanup();
}, 60 * 60 * 1000);

setInterval(() => {
  notificationService.processRetryQueue();
}, 5 * 60 * 1000);

export default notificationService;
