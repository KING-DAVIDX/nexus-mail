'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

class MySMTPClient extends EventEmitter {
    constructor(options = {}) {
        super();
        
        this.options = {
            host: options.host || 'smtp.gmail.com',
            port: options.port || 465,
            secure: options.secure || false,
            auth: options.auth || {},
            debug: options.debug || false,
            timeout: options.timeout || 30000,
            ...options
        };
        
        this.socket = null;
        this.connected = false;
        this.authenticated = false;
        this.buffer = '';
        this.responseHandlers = [];
        this.currentHandler = null;
    }

    connect() {
        return new Promise((resolve, reject) => {
            if (this.connected) {
                resolve();
                return;
            }

            const connectionOptions = {
                host: this.options.host,
                port: this.options.port
            };

            const onConnect = () => {
                this.connected = true;
                this._setupSocketHandlers();
                this._waitForGreeting().then(resolve).catch(reject);
            };

            const onError = (error) => {
                reject(new Error(`Connection failed: ${error.message}`));
            };

            if (this.options.secure) {
                this.socket = tls.connect(connectionOptions, onConnect);
            } else {
                this.socket = net.connect(connectionOptions, onConnect);
            }

            this.socket.once('error', onError);
            
            setTimeout(() => {
                if (!this.connected) {
                    this.socket?.destroy();
                    reject(new Error('Connection timeout'));
                }
            }, this.options.timeout);
        });
    }

    _setupSocketHandlers() {
        this.socket.on('data', (data) => this._onData(data));
        this.socket.on('error', (error) => this._onError(error));
        this.socket.on('close', () => this._onClose());
        this.socket.on('end', () => this._onEnd());
    }

    _onData(data) {
        this.buffer += data.toString();
        this._processBuffer();
    }

    _onError(error) {
        this.emit('error', error);
    }

    _onClose() {
        this.connected = false;
        this.emit('close');
    }

    _onEnd() {
        this.connected = false;
        this.emit('end');
    }

    _processBuffer() {
        const lines = this.buffer.split('\r\n');
        this.buffer = lines.pop() || '';
        
        for (const line of lines) {
            if (line.trim()) {
                this._handleResponse(line);
            }
        }
    }

    _handleResponse(line) {
        if (this.options.debug) {
            console.log('SERVER:', line);
        }

        this.emit('response', line);

        if (this.currentHandler) {
            this.currentHandler(line);
            this.currentHandler = null;
        }
    }

    _sendCommand(command, logCommand = null) {
        return new Promise((resolve, reject) => {
            if (!this.connected) {
                reject(new Error('Not connected'));
                return;
            }

            if (this.options.debug) {
                console.log('CLIENT:', logCommand || command);
            }

            this.currentHandler = (response) => {
                const code = parseInt(response.substring(0, 3));
                if (code >= 200 && code < 400) {
                    resolve(response);
                } else {
                    reject(new Error(`SMTP Error: ${response}`));
                }
            };

            this.socket.write(command + '\r\n');
        });
    }

    _waitForGreeting() {
        return new Promise((resolve, reject) => {
            this.currentHandler = (response) => {
                const code = parseInt(response.substring(0, 3));
                if (code === 220) {
                    resolve(response);
                } else {
                    reject(new Error(`Invalid greeting: ${response}`));
                }
            };
        });
    }

    async startTLS() {
        await this._sendCommand('STARTTLS');
        
        return new Promise((resolve, reject) => {
            const options = {
                socket: this.socket,
                host: this.options.host
            };

            this.socket = tls.connect(options, () => {
                this._setupSocketHandlers();
                resolve();
            });

            this.socket.once('error', reject);
        });
    }

    async ehlo() {
        return await this._sendCommand(`EHLO ${this._getHostname()}`);
    }

    async login() {
        if (!this.options.auth.user || !this.options.auth.pass) {
            throw new Error('Username and password required for authentication');
        }

        try {
            await this._sendCommand('AUTH LOGIN');
            await this._sendCommand(
                Buffer.from(this.options.auth.user).toString('base64'),
                'AUTH LOGIN username'
            );
            await this._sendCommand(
                Buffer.from(this.options.auth.pass).toString('base64'),
                'AUTH LOGIN password'
            );
            this.authenticated = true;
            return true;
        } catch (error) {
            try {
                const credentials = Buffer.from(
                    `\u0000${this.options.auth.user}\u0000${this.options.auth.pass}`
                ).toString('base64');
                await this._sendCommand(
                    `AUTH PLAIN ${credentials}`,
                    `AUTH PLAIN ${Buffer.from(`\u0000${this.options.auth.user}\u0000***`).toString('base64')}`
                );
                this.authenticated = true;
                return true;
            } catch (plainError) {
                try {
                    await this._authCramMD5();
                    this.authenticated = true;
                    return true;
                } catch (cramError) {
                    throw new Error(`Authentication failed: ${error.message}`);
                }
            }
        }
    }

    _authCramMD5() {
        return new Promise((resolve, reject) => {
            this._sendCommand('AUTH CRAM-MD5').then(response => {
                const challenge = response.substring(4);
                const decodedChallenge = Buffer.from(challenge, 'base64').toString();
                const hmac = crypto.createHmac('md5', this.options.auth.pass);
                hmac.update(decodedChallenge);
                const hmacDigest = hmac.digest('hex');
                const responseData = Buffer.from(`${this.options.auth.user} ${hmacDigest}`).toString('base64');
                this._sendCommand(responseData, 'AUTH CRAM-MD5 response')
                    .then(resolve)
                    .catch(reject);
            }).catch(reject);
        });
    }

    async sendMail(mailOptions) {
        if (!this.authenticated) {
            throw new Error('Not authenticated');
        }

        const { from, to, subject, text, html, attachments, headers, priority, readReceipt, calendarEvent } = mailOptions;

        await this._sendCommand(`MAIL FROM:<${from}>`);

        const recipients = Array.isArray(to) ? to : [to];
        for (const recipient of recipients) {
            await this._sendCommand(`RCPT TO:<${recipient}>`);
        }

        await this._sendCommand('DATA');

        const message = this._buildMessage(from, recipients, subject, text, html, attachments, headers, priority, readReceipt, calendarEvent);
        await this._sendCommand(message + '\r\n.');

        return { messageId: this._generateMessageId(), accepted: recipients };
    }

    _buildMessage(from, to, subject, text, html, attachments = [], headers = {}, priority, readReceipt, calendarEvent) {
        const messageId = this._generateMessageId();
        const date = new Date().toUTCString();
        const boundary = `boundary_${crypto.randomBytes(8).toString('hex')}`;
        const relatedBoundary = `related_${crypto.randomBytes(8).toString('hex')}`;
        const alternativeBoundary = `alternative_${crypto.randomBytes(8).toString('hex')}`;
        
        let message = [
            `Message-ID: <${messageId}>`,
            `Date: ${date}`,
            `From: ${from}`,
            `To: ${Array.isArray(to) ? to.join(', ') : to}`,
            `Subject: ${subject}`,
            'MIME-Version: 1.0'
        ];

        // Add custom headers
        for (const [key, value] of Object.entries(headers)) {
            message.push(`${key}: ${value}`);
        }

        // Add priority header
        if (priority) {
            const priorityMap = {
                high: '1 (High)',
                normal: '3 (Normal)',
                low: '5 (Low)'
            };
            const priorityValue = priorityMap[priority] || priorityMap.normal;
            message.push(`Priority: ${priorityValue}`);
            message.push(`X-Priority: ${priorityValue}`);
            message.push(`Importance: ${priority}`);
        }

        // Add read receipt
        if (readReceipt) {
            message.push(`Disposition-Notification-To: ${readReceipt}`);
            message.push(`X-Confirm-Reading-To: ${readReceipt}`);
            message.push('Return-Receipt-To: 1');
        }

        const hasAttachments = attachments && attachments.length > 0;
        const hasEmbeddedImages = html && html.includes('cid:');
        const hasCalendarEvent = calendarEvent && calendarEvent.content;

        if (hasAttachments || hasEmbeddedImages || hasCalendarEvent) {
            message.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
            message.push('');
            message.push(`--${boundary}`);
        }

        // Handle calendar events
        if (hasCalendarEvent) {
            message.push(`Content-Type: text/calendar; method=${calendarEvent.method || 'REQUEST'}; charset="UTF-8"`);
            message.push('Content-Transfer-Encoding: base64');
            message.push('');
            message.push(Buffer.from(calendarEvent.content).toString('base64'));
            message.push('');
            message.push(`--${boundary}`);
        }

        // Handle HTML with embedded images
        if (hasEmbeddedImages) {
            message.push(`Content-Type: multipart/related; boundary="${relatedBoundary}"`);
            message.push('');
            message.push(`--${relatedBoundary}`);
        }

        // Text/HTML content
        if (html && text) {
            message.push(`Content-Type: multipart/alternative; boundary="${alternativeBoundary}"`);
            message.push('');
            message.push(`--${alternativeBoundary}`);
            message.push('Content-Type: text/plain; charset="UTF-8"');
            message.push('Content-Transfer-Encoding: 7bit');
            message.push('');
            message.push(text);
            message.push('');
            message.push(`--${alternativeBoundary}`);
            message.push('Content-Type: text/html; charset="UTF-8"');
            message.push('Content-Transfer-Encoding: 7bit');
            message.push('');
            message.push(html);
            message.push('');
            message.push(`--${alternativeBoundary}--`);
        } else if (html) {
            message.push('Content-Type: text/html; charset="UTF-8"');
            message.push('Content-Transfer-Encoding: 7bit');
            message.push('');
            message.push(html);
        } else {
            message.push('Content-Type: text/plain; charset="UTF-8"');
            message.push('Content-Transfer-Encoding: 7bit');
            message.push('');
            message.push(text);
        }

        // Handle embedded images
        if (hasEmbeddedImages && attachments) {
            const embeddedAttachments = attachments.filter(att => att.cid);
            for (const attachment of embeddedAttachments) {
                message.push('');
                message.push(`--${relatedBoundary}`);
                message.push(`Content-Type: ${attachment.contentType || 'application/octet-stream'}`);
                message.push('Content-Transfer-Encoding: base64');
                message.push(`Content-ID: <${attachment.cid}>`);
                message.push('Content-Disposition: inline');
                message.push('');
                message.push(this._getAttachmentContent(attachment));
            }
            message.push('');
            message.push(`--${relatedBoundary}--`);
        }

        // Handle regular attachments
        if (hasAttachments) {
            const regularAttachments = attachments.filter(att => !att.cid);
            for (const attachment of regularAttachments) {
                message.push('');
                message.push(`--${boundary}`);
                message.push(`Content-Type: ${attachment.contentType || 'application/octet-stream'}`);
                message.push('Content-Transfer-Encoding: base64');
                message.push(`Content-Disposition: attachment; filename="${attachment.filename || 'file'}"`);
                if (attachment.contentId) {
                    message.push(`Content-ID: <${attachment.contentId}>`);
                }
                message.push('');
                message.push(this._getAttachmentContent(attachment));
            }
        }

        if (hasAttachments || hasEmbeddedImages || hasCalendarEvent) {
            message.push('');
            message.push(`--${boundary}--`);
        }

        return message.join('\r\n');
    }

    _getAttachmentContent(attachment) {
        if (attachment.content) {
            return Buffer.from(attachment.content).toString('base64');
        } else if (attachment.path) {
            try {
                const fileContent = fs.readFileSync(attachment.path);
                return fileContent.toString('base64');
            } catch (error) {
                throw new Error(`Could not read attachment file: ${attachment.path}`);
            }
        } else if (attachment.buffer) {
            return attachment.buffer.toString('base64');
        } else {
            throw new Error('Attachment must have content, path, or buffer property');
        }
    }

    _generateMessageId() {
        return `${Date.now()}${crypto.randomBytes(8).toString('hex')}@${this._getHostname()}`;
    }

    _getHostname() {
        try {
            return require('os').hostname() || 'localhost';
        } catch {
            return 'localhost';
        }
    }

    async quit() {
        try {
            await this._sendCommand('QUIT');
        } catch (error) {
        } finally {
            this.close();
        }
    }

    close() {
        if (this.socket) {
            this.socket.destroy();
            this.socket = null;
        }
        this.connected = false;
        this.authenticated = false;
    }
}

async function sendMail(options, mailOptions) {
    const client = new MySMTPClient(options);
    
    try {
        await client.connect();
        await client._waitForGreeting();
        const ehloResponse = await client.ehlo();
        if (!options.secure && ehloResponse.includes('STARTTLS')) {
            await client.startTLS();
            await client.ehlo();
        }
        await client.login();
        const result = await client.sendMail(mailOptions);
        await client.quit();
        return result;
    } catch (error) {
        client.close();
        throw error;
    }
}

// Helper function to create calendar event
function createCalendarEvent({ start, end, summary, description, location, organizer, attendees, method = 'REQUEST' }) {
    const formatDate = (date) => date.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
    
    const ical = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//MySMTPClient//EN',
        'METHOD:' + method,
        'BEGIN:VEVENT',
        'UID:' + crypto.randomBytes(16).toString('hex'),
        'DTSTAMP:' + formatDate(new Date()),
        'DTSTART:' + formatDate(start),
        'DTEND:' + formatDate(end),
        'SUMMARY:' + (summary || ''),
        'DESCRIPTION:' + (description || ''),
        'LOCATION:' + (location || ''),
    ];

    if (organizer) {
        ical.push(`ORGANIZER:mailto:${organizer}`);
    }

    if (attendees && attendees.length > 0) {
        for (const attendee of attendees) {
            ical.push(`ATTENDEE:mailto:${attendee}`);
        }
    }

    ical.push('END:VEVENT');
    ical.push('END:VCALENDAR');

    return ical.join('\r\n');
}

module.exports = {
    MySMTPClient,
    sendMail,
    createCalendarEvent
};
