'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

// Predefined email services configuration
const EMAIL_SERVICES = {
    gmail: {
        host: 'smtp.gmail.com',
        port: 587,
        secure: false
    },
    outlook: {
        host: 'smtp-mail.outlook.com',
        port: 587,
        secure: false
    },
    yahoo: {
        host: 'smtp.mail.yahoo.com',
        port: 587,
        secure: false
    },
    aol: {
        host: 'smtp.aol.com',
        port: 587,
        secure: false
    },
    zoho: {
        host: 'smtp.zoho.com',
        port: 587,
        secure: false
    },
    icloud: {
        host: 'smtp.mail.me.com',
        port: 587,
        secure: false
    },
    office365: {
        host: 'smtp.office365.com',
        port: 587,
        secure: false
    },
    // Add more services as needed
    custom: {
        // For custom SMTP servers
        host: '',
        port: 587,
        secure: false
    }
};

class MySMTPClient extends EventEmitter {
    constructor(options = {}) {
        super();
        
        // Handle service-based configuration
        if (options.service && EMAIL_SERVICES[options.service]) {
            const serviceConfig = EMAIL_SERVICES[options.service];
            this.options = {
                ...serviceConfig,
                ...options,
                auth: options.auth || {}
            };
        } else {
            this.options = {
                host: options.host || 'smtp.gmail.com',
                port: options.port || 587,
                secure: options.secure || false,
                auth: options.auth || {},
                debug: options.debug || false,
                timeout: options.timeout || 30000,
                ...options
            };
        }
        
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

        const { from, to, subject, text, html, attachments = [] } = mailOptions;

        await this._sendCommand(`MAIL FROM:<${from}>`);

        const recipients = Array.isArray(to) ? to : [to];
        for (const recipient of recipients) {
            await this._sendCommand(`RCPT TO:<${recipient}>`);
        }

        await this._sendCommand('DATA');

        const message = await this._buildMessage(from, recipients, subject, text, html, attachments);
        await this._sendCommand(message + '\r\n.');

        return { messageId: this._generateMessageId(), accepted: recipients };
    }

    async _buildMessage(from, to, subject, text, html, attachments) {
        const messageId = this._generateMessageId();
        const date = new Date().toUTCString();
        const boundary = `boundary_${crypto.randomBytes(8).toString('hex')}`;
        
        let message = [
            `Message-ID: <${messageId}>`,
            `Date: ${date}`,
            `From: ${from}`,
            `To: ${Array.isArray(to) ? to.join(', ') : to}`,
            `Subject: ${subject}`,
            'MIME-Version: 1.0'
        ];

        // Check if we have attachments or both text and html
        const hasAttachments = attachments && attachments.length > 0;
        const hasBothTextAndHtml = text && html;

        if (hasAttachments || hasBothTextAndHtml) {
            const mainBoundary = `main_${boundary}`;
            message.push(`Content-Type: multipart/mixed; boundary="${mainBoundary}"`);
            message.push('');
            message.push(`--${mainBoundary}`);

            if (hasBothTextAndHtml) {
                const altBoundary = `alt_${boundary}`;
                message.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
                message.push('');
                message.push(`--${altBoundary}`);
                message.push('Content-Type: text/plain; charset="UTF-8"');
                message.push('Content-Transfer-Encoding: 7bit');
                message.push('');
                message.push(text || '');
                message.push('');
                message.push(`--${altBoundary}`);
                message.push('Content-Type: text/html; charset="UTF-8"');
                message.push('Content-Transfer-Encoding: 7bit');
                message.push('');
                message.push(html || '');
                message.push('');
                message.push(`--${altBoundary}--`);
                message.push('');
                message.push(`--${mainBoundary}`);
            } else if (text) {
                message.push('Content-Type: text/plain; charset="UTF-8"');
                message.push('Content-Transfer-Encoding: 7bit');
                message.push('');
                message.push(text || '');
                message.push('');
                message.push(`--${mainBoundary}`);
            } else if (html) {
                message.push('Content-Type: text/html; charset="UTF-8"');
                message.push('Content-Transfer-Encoding: 7bit');
                message.push('');
                message.push(html || '');
                message.push('');
                message.push(`--${mainBoundary}`);
            }

            // Add attachments
            for (const attachment of attachments) {
                const attachmentData = await this._processAttachment(attachment);
                message.push(`Content-Type: ${attachmentData.contentType}; name="${attachmentData.filename}"`);
                message.push('Content-Transfer-Encoding: base64');
                message.push(`Content-Disposition: attachment; filename="${attachmentData.filename}"`);
                message.push('');
                message.push(attachmentData.content);
                message.push('');
                message.push(`--${mainBoundary}`);
            }

            message[message.length - 1] = message[message.length - 1] + '--';
        } else {
            // Simple message without attachments
            if (html) {
                message.push('Content-Type: text/html; charset="UTF-8"');
            } else {
                message.push('Content-Type: text/plain; charset="UTF-8"');
            }
            message.push('Content-Transfer-Encoding: 7bit');
            message.push('');
            message.push(html || text || '');
        }

        return message.join('\r\n');
    }

    async _processAttachment(attachment) {
        let filename, content, contentType;
        
        if (typeof attachment === 'string') {
            // File path
            filename = path.basename(attachment);
            content = fs.readFileSync(attachment);
            contentType = this._getMimeType(attachment) || 'application/octet-stream';
        } else if (attachment.filename && attachment.content) {
            // Object with filename and content
            filename = attachment.filename;
            content = Buffer.isBuffer(attachment.content) ? 
                     attachment.content : 
                     Buffer.from(attachment.content);
            contentType = attachment.contentType || 
                         this._getMimeType(filename) || 
                         'application/octet-stream';
        } else {
            throw new Error('Invalid attachment format');
        }

        return {
            filename,
            content: content.toString('base64'),
            contentType
        };
    }

    _getMimeType(filename) {
        const ext = path.extname(filename).toLowerCase();
        const mimeTypes = {
            '.txt': 'text/plain',
            '.html': 'text/html',
            '.htm': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.pdf': 'application/pdf',
            '.zip': 'application/zip',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.svg': 'image/svg+xml',
            '.mp3': 'audio/mpeg',
            '.wav': 'audio/wav',
            '.mp4': 'video/mp4',
            '.avi': 'video/x-msvideo'
        };
        
        return mimeTypes[ext] || 'application/octet-stream';
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
            // Ignore errors during quit
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

// User-friendly function to send email
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

// High-level user-friendly function
async function sendEmail(config) {
    const { service, auth, from, to, subject, text, html, attachments, debug = false } = config;
    
    const options = {
        service,
        auth: {
            user: auth.user,
            pass: auth.pass
        },
        debug
    };

    const mailOptions = {
        from,
        to,
        subject,
        text,
        html,
        attachments
    };

    return await sendMail(options, mailOptions);
}

// Export available services
function getAvailableServices() {
    return Object.keys(EMAIL_SERVICES);
}

module.exports = {
    MySMTPClient,
    sendMail,
    sendEmail,
    getAvailableServices,
    EMAIL_SERVICES
};
