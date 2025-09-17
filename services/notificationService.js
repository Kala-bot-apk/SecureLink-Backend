// services/notificationService.js
import { admin } from '../firebaseAdmin.js';

export class NotificationService {
  constructor() {
    this.messaging = admin.messaging();
  }

  async sendNotification(notificationData) {
    try {
      const { title, body, data, token } = notificationData;

      if (!token) {
        throw new Error('FCM token is required');
      }

      const message = {
        token,
        notification: {
          title,
          body,
        },
        data: {
          ...data,
          timestamp: Date.now().toString(),
        },
        android: {
          priority: 'high',
          notification: {
            sound: 'default',
            priority: 'high',
            channelId: 'chat_messages',
          },
        },
        apns: {
          payload: {
            aps: {
              sound: 'default',
              badge: 1,
              alert: {
                title,
                body,
              },
            },
          },
        },
      };

      const response = await this.messaging.send(message);
      console.log('✅ Notification sent successfully:', response);
      return response;
    } catch (error) {
      console.error('❌ Error sending notification:', error);
      throw error;
    }
  }

  async sendBulkNotifications(notifications) {
    try {
      const messages = notifications.map(notif => ({
        token: notif.token,
        notification: {
          title: notif.title,
          body: notif.body,
        },
        data: {
          ...notif.data,
          timestamp: Date.now().toString(),
        },
        android: {
          priority: 'high',
          notification: {
            sound: 'default',
            priority: 'high',
          },
        },
        apns: {
          payload: {
            aps: {
              sound: 'default',
              badge: 1,
            },
          },
        },
      }));

      const response = await this.messaging.sendAll(messages);
      console.log(`✅ Bulk notifications sent: ${response.successCount}/${messages.length}`);
      return response;
    } catch (error) {
      console.error('❌ Error sending bulk notifications:', error);
      throw error;
    }
  }
}
