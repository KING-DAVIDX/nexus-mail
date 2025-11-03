'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const EMAIL_SERVICES = {
    gmail: { host: 'smtp.gmail.com', port: 587, secure: false },
    outlook: { host: 'smtp-mail.outlook.com', port: 587, secure: false },
    yahoo: { host: 'smtp.mail.yahoo.com', port: 587, secure: false },
    aol: { host: 'smtp.aol.com', port: 587, secure: false },
    zoho: { host: 'smtp.zoho.com', port: 587, secure: false },
    icloud: { host: 'smtp.mail.me.com', port: 587, secure: false },
    office365: { host: 'smtp.office365.com', port: 587, secure: false },
    custom: { host: '', port: 587, secure: false }
};

class MySMTPClient extends EventEmitter {
    constructor(options = {}) {
        super();

        if (options.service && EMAIL_SERVICES[options.service]) {
            const serviceConfig = EMAIL_SERVICES[options.service];
            this.options = { ...serviceConfig, ...options, auth: options.auth || {} };
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
        this.currentHandler = null;
    }

    connect() {
        return new Promise((resolve, reject) => {
            if (this.connected) return resolve();

            const connectionOptions = {
                host: this.options.host,
                port: this.options.port,
            };

            const onError = (err) => reject(new Error(`Connection failed: ${err.message}`));

            const handleConnect = () => {
                this.connected = true;
                this._setupSocketHandlers();

                // Wait for the greeting
                this.currentHandler = (line) => {
                    const code = parseInt(line.substring(0, 3));
                    if (code === 220) {
                        resolve(line);
                    } else {
                        reject(new Error(`Unexpected greeting: ${line}`));
                    }
                };
            };

            this.socket = this.options.secure
                ? tls.connect(connectionOptions, handleConnect)
                : net.connect(connectionOptions, handleConnect);

            this.socket.once("error", onError);

            setTimeout(() => {
                if (!this.connected) {
                    this.socket?.destroy();
                    reject(new Error("Connection timeout"));
                }
            }, this.options.timeout);
        });
    }

    _setupSocketHandlers() {
        this.socket.on('data', (data) => this._onData(data));
        this.socket.on('error', (err) => this._onError(err));
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
            if (line.trim()) this._handleResponse(line);
        }
    }

    _handleResponse(line) {
        if (this.options.debug) console.log('SERVER:', line);
        this.emit('response', line);

        if (this.currentHandler) {
            const handler = this.currentHandler;
            this.currentHandler = null;
            handler(line);
        }
    }

    _sendCommand(command, logCommand = null) {
        return new Promise((resolve, reject) => {
            if (!this.connected) return reject(new Error('Not connected'));

            if (this.options.debug) console.log('CLIENT:', logCommand || command);

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

    async startTLS() {
        await this._sendCommand('STARTTLS');
        return new Promise((resolve, reject) => {
            const options = { socket: this.socket, host: this.options.host };
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
        const { user, pass } = this.options.auth;
        if (!user || !pass) throw new Error('Username and password required for authentication');

        try {
            await this._sendCommand('AUTH LOGIN');
            await this._sendCommand(Buffer.from(user).toString('base64'), 'AUTH LOGIN username');
            await this._sendCommand(Buffer.from(pass).toString('base64'), 'AUTH LOGIN password');
            this.authenticated = true;
        } catch {
            // fallback plain
            const credentials = Buffer.from(`\u0000${user}\u0000${pass}`).toString('base64');
            await this._sendCommand(`AUTH PLAIN ${credentials}`, 'AUTH PLAIN');
            this.authenticated = true;
        }
        return true;
    }

    async sendMail(mailOptions) {
        if (!this.authenticated) throw new Error('Not authenticated');

        const { from, to, subject, text, html, attachments = [] } = mailOptions;
        await this._sendCommand(`MAIL FROM:<${from}>`);

        const recipients = Array.isArray(to) ? to : [to];
        for (const rcpt of recipients) {
            await this._sendCommand(`RCPT TO:<${rcpt}>`);
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

        const hasAttachments = attachments && attachments.length > 0;
        const hasBothTextAndHtml = text && html;

        if (hasAttachments || hasBothTextAndHtml) {
            const mainBoundary = `main_${boundary}`;
            message.push(`Content-Type: multipart/mixed; boundary="${mainBoundary}"`, '', `--${mainBoundary}`);

            if (hasBothTextAndHtml) {
                const altBoundary = `alt_${boundary}`;
                message.push(
                    `Content-Type: multipart/alternative; boundary="${altBoundary}"`, '',
                    `--${altBoundary}`,
                    'Content-Type: text/plain; charset="UTF-8"',
                    'Content-Transfer-Encoding: 7bit', '', text, '',
                    `--${altBoundary}`,
                    'Content-Type: text/html; charset="UTF-8"',
                    'Content-Transfer-Encoding: 7bit', '', html, '',
                    `--${altBoundary}--`, '', `--${mainBoundary}`
                );
            } else if (text || html) {
                message.push(
                    `Content-Type: ${html ? 'text/html' : 'text/plain'}; charset="UTF-8"`,
                    'Content-Transfer-Encoding: 7bit', '',
                    html || text, '',
                    `--${mainBoundary}`
                );
            }

            for (const attachment of attachments) {
                const att = await this._processAttachment(attachment);
                message.push(
                    `Content-Type: ${att.contentType}; name="${att.filename}"`,
                    'Content-Transfer-Encoding: base64',
                    `Content-Disposition: attachment; filename="${att.filename}"`, '',
                    att.content, '', `--${mainBoundary}`
                );
            }

            message[message.length - 1] = message[message.length - 1] + '--';
        } else {
            message.push(
                `Content-Type: ${html ? 'text/html' : 'text/plain'}; charset="UTF-8"`,
                'Content-Transfer-Encoding: 7bit', '',
                html || text || ''
            );
        }

        return message.join('\r\n');
    }

    async _processAttachment(attachment) {
        let filename, content, contentType;
        if (typeof attachment === 'string') {
            filename = path.basename(attachment);
            content = fs.readFileSync(attachment);
            contentType = this._getMimeType(attachment);
        } else if (attachment.filename && attachment.content) {
            filename = attachment.filename;
            content = Buffer.isBuffer(attachment.content)
                ? attachment.content
                : Buffer.from(attachment.content);
            contentType = attachment.contentType || this._getMimeType(filename);
        } else {
            throw new Error('Invalid attachment format');
        }
        return { filename, content: content.toString('base64'), contentType };
    }

    _getMimeType(filename) {
        const ext = path.extname(filename).toLowerCase();
        const mime = {
            '.txt': 'text/plain', '.html': 'text/html', '.js': 'application/javascript',
            '.json': 'application/json', '.pdf': 'application/pdf',
            '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif'
        };
        return mime[ext] || 'application/octet-stream';
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
        } catch { }
        this.close();
    }

    close() {
        if (this.socket) this.socket.destroy();
        this.socket = null;
        this.connected = false;
        this.authenticated = false;
    }
}

async function sendMail(options, mailOptions) {
    const client = new MySMTPClient(options);
    try {
        await client.connect();
        await client.ehlo();
        if (!options.secure) {
            await client.startTLS().catch(() => {});
            await client.ehlo();
        }
        await client.login();
        const result = await client.sendMail(mailOptions);
        await client.quit();
        return result;
    } catch (err) {
        client.close();
        throw err;
    }
}

async function sendEmail(config) {
    const { service, auth, from, to, subject, text, html, attachments, debug = false } = config;
    const options = { service, auth, debug };
    const mailOptions = { from, to, subject, text, html, attachments };
    return await sendMail(options, mailOptions);
}

function getAvailableServices() {
    return Object.keys(EMAIL_SERVICES);
}

module.exports = { MySMTPClient, sendMail, sendEmail, getAvailableServices, EMAIL_SERVICES };
