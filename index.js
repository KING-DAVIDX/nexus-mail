'use strict';

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');

const EMAIL_SERVICES = {
    gmail:      { host: 'smtp.gmail.com',      port: 465, secure: true },
    outlook:    { host: 'smtp-mail.outlook.com', port: 587, secure: false },
    yahoo:      { host: 'smtp.mail.yahoo.com', port: 465, secure: true },
    aol:        { host: 'smtp.aol.com',        port: 465, secure: true },
    zoho:       { host: 'smtp.zoho.com',       port: 465, secure: true },
    icloud:     { host: 'smtp.mail.me.com',    port: 587, secure: false },
    office365:  { host: 'smtp.office365.com',  port: 587, secure: false },
    custom:     { host: '', port: 587, secure: false }
};

class nexusClient extends EventEmitter {
    constructor(options = {}) {
        super();

        if (options.service && EMAIL_SERVICES[options.service]) {
            const serviceConfig = EMAIL_SERVICES[options.service];
            this.options = { ...serviceConfig, ...options, auth: options.auth || {} };
        } else {
            this.options = {
                host: options.host || 'smtp.gmail.com',
                port: options.port || 465,
                secure: options.secure !== undefined ? options.secure : true,
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
            const connectionOptions = { host: this.options.host, port: this.options.port };
            const onError = (err) => reject(new Error(`Connection failed: ${err.message}`));

            const handleConnect = () => {
                this.connected = true;
                this._setupSocketHandlers();
                this.currentHandler = (line) => {
                    const code = parseInt(line.substring(0, 3));
                    if (code === 220) {
                        if (this.options.debug) console.log('✅ Connected:', line);
                        resolve(line);
                    } else {
                        reject(new Error(`Unexpected greeting: ${line}`));
                    }
                };
            };

            if (this.options.debug)
                console.log(`🔌 Connecting to ${this.options.host}:${this.options.port} (secure=${this.options.secure})`);

            this.socket = this.options.secure
                ? tls.connect(connectionOptions, handleConnect)
                : net.connect(connectionOptions, handleConnect);

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
        this.socket.on('data', (d) => this._onData(d));
        this.socket.on('error', (e) => this._onError(e));
        this.socket.on('close', () => this._onClose());
        this.socket.on('end', () => this._onEnd());
    }

    _onData(data) {
        this.buffer += data.toString();
        this._processBuffer();
    }

    _onError(e) { this.emit('error', e); }
    _onClose() { this.connected = false; this.emit('close'); }
    _onEnd() { this.connected = false; this.emit('end'); }

    _processBuffer() {
        const lines = this.buffer.split('\r\n');
        this.buffer = lines.pop() || '';
        for (const line of lines) {
            if (line.trim()) this._handleResponse(line);
        }
    }

    _handleResponse(line) {
        if (this.options.debug) console.log('📩 SERVER:', line);
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
            if (this.options.debug) console.log('📤 CLIENT:', logCommand || command);
            this.currentHandler = (response) => {
                const code = parseInt(response.substring(0, 3));
                if (code >= 200 && code < 400) resolve(response);
                else reject(new Error(`SMTP Error: ${response}`));
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
                if (this.options.debug) console.log('🔒 TLS connection established');
                resolve();
            });
            this.socket.once('error', reject);
        });
    }

    async ehlo() { return await this._sendCommand(`EHLO ${this._getHostname()}`); }

    async login() {
        const { user, pass } = this.options.auth;
        if (!user || !pass) throw new Error('Username and password required for authentication');
        try {
            await this._sendCommand('AUTH LOGIN');
            await this._sendCommand(Buffer.from(user).toString('base64'), 'AUTH LOGIN username');
            await this._sendCommand(Buffer.from(pass).toString('base64'), 'AUTH LOGIN password');
            this.authenticated = true;
        } catch {
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
        for (const rcpt of recipients) await this._sendCommand(`RCPT TO:<${rcpt}>`);
        await this._sendCommand('DATA');
        const message = await this._buildMessage(from, recipients, subject, text, html, attachments);
        await this._sendCommand(message + '\r\n.');
        return { messageId: this._generateMessageId(), accepted: recipients };
    }

    async _buildMessage(from, to, subject, text, html, attachments) {
        const messageId = this._generateMessageId();
        const date = new Date().toUTCString();
        const boundary = `b_${crypto.randomBytes(8).toString('hex')}`;
        let message = [
            `Message-ID: <${messageId}>`,
            `Date: ${date}`,
            `From: ${from}`,
            `To: ${Array.isArray(to) ? to.join(', ') : to}`,
            `Subject: ${subject}`,
            'MIME-Version: 1.0'
        ];

        const inlineFiles = attachments.filter(a => a.cid);
        const fileAttachments = attachments.filter(a => !a.cid);
        const hasBothTextAndHtml = text && html;
        const needMultipart = fileAttachments.length > 0 || inlineFiles.length > 0 || hasBothTextAndHtml;

        if (!needMultipart) {
            message.push(
                `Content-Type: ${html ? 'text/html' : 'text/plain'}; charset="UTF-8"`,
                'Content-Transfer-Encoding: 7bit', '',
                html || text || ''
            );
            return message.join('\r\n');
        }

        const mainBoundary = `main_${boundary}`;
        message.push(`Content-Type: multipart/mixed; boundary="${mainBoundary}"`, '', `--${mainBoundary}`);

        if (hasBothTextAndHtml || inlineFiles.length > 0) {
            const altBoundary = `alt_${boundary}`;
            message.push(`Content-Type: multipart/related; boundary="${altBoundary}"`, '', `--${altBoundary}`);

            if (hasBothTextAndHtml) {
                const textBoundary = `text_${boundary}`;
                message.push(`Content-Type: multipart/alternative; boundary="${textBoundary}"`, '',
                    `--${textBoundary}`,
                    'Content-Type: text/plain; charset="UTF-8"',
                    'Content-Transfer-Encoding: 7bit', '', text || '', '',
                    `--${textBoundary}`,
                    'Content-Type: text/html; charset="UTF-8"',
                    'Content-Transfer-Encoding: 7bit', '', html || '', '',
                    `--${textBoundary}--`);
            } else {
                message.push(
                    'Content-Type: text/html; charset="UTF-8"',
                    'Content-Transfer-Encoding: 7bit', '',
                    html || text || ''
                );
            }

            for (const inline of inlineFiles) {
                const att = await this._processAttachment(inline);
                message.push(
                    '', `--${altBoundary}`,
                    `Content-Type: ${att.contentType}; name="${att.filename}"`,
                    'Content-Transfer-Encoding: base64',
                    `Content-Disposition: inline; filename="${att.filename}"`,
                    `Content-ID: <${inline.cid}>`, '',
                    att.content
                );
            }

            message.push('', `--${altBoundary}--`, '', `--${mainBoundary}`);
        } else {
            message.push(
                `Content-Type: ${html ? 'text/html' : 'text/plain'}; charset="UTF-8"`,
                'Content-Transfer-Encoding: 7bit', '',
                html || text || '', '',
                `--${mainBoundary}`
            );
        }

        for (const attachment of fileAttachments) {
            const att = await this._processAttachment(attachment);
            message.push(
                `Content-Type: ${att.contentType}; name="${att.filename}"`,
                'Content-Transfer-Encoding: base64',
                `Content-Disposition: attachment; filename="${att.filename}"`, '',
                att.content, '', `--${mainBoundary}`
            );
        }

        message[message.length - 1] = message[message.length - 1] + '--';
        return message.join('\r\n');
    }

    async _processAttachment(att) {
        let filename, content, contentType;
        if (att.path && fs.existsSync(att.path)) {
            filename = att.filename || path.basename(att.path);
            content = fs.readFileSync(att.path);
            contentType = att.contentType || this._getMimeType(att.path);
        } else if (att.filename && att.content) {
            filename = att.filename;
            content = Buffer.isBuffer(att.content) ? att.content : Buffer.from(att.content);
            contentType = att.contentType || this._getMimeType(filename);
        } else throw new Error('Invalid attachment');
        return { filename, content: content.toString('base64'), contentType };
    }

    _getMimeType(filename) {
        const ext = path.extname(filename).toLowerCase();
        const mime = {
            '.txt': 'text/plain', '.html': 'text/html', '.pdf': 'application/pdf',
            '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif'
        };
        return mime[ext] || 'application/octet-stream';
    }

    _generateMessageId() {
        return `${Date.now()}${crypto.randomBytes(8).toString('hex')}@${this._getHostname()}`;
    }

    _getHostname() {
        try { return require('os').hostname() || 'localhost'; }
        catch { return 'localhost'; }
    }

    async quit() { try { await this._sendCommand('QUIT'); } catch {} this.close(); }
    close() { if (this.socket) this.socket.destroy(); this.socket = null; this.connected = false; this.authenticated = false; }
}

async function sendMail(options, mailOptions) {
    const client = new nexusClient(options);
    try {
        await client.connect();
        await client.ehlo();
        if (!client.options.secure) { // For STARTTLS mode
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

function getAvailableServices() { return Object.keys(EMAIL_SERVICES); }

module.exports = { nexusClient, sendMail, sendEmail, getAvailableServices, EMAIL_SERVICES };
