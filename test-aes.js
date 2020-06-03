const aesJs = require("aes-js");
const jsSHA = require("jssha");
const base64 = require("base64-js");
const Buffer = require("buffer").Buffer;
const encodingAesKey = "jWmYm7qr5nMoAUwZRjGtBxmz3KA1tkAj3ykkR6q2B2C";
const receiveId = "wx5823bf96d3bd56c7";
const token = "QDG6eK";
const BLOCK_SIZE = 32;
let msg_signature = "477715d11cdb4164915debcba66cb864d751f3e6";
let timestamp = "1409659813";
let nonce = "1372623149";
let echostr ="RypEvHKD8QQKFhvQ6QleEB4J58tiPdvo+rtK1I9qca6aM/wvqnLSV5zEPeusUiX5L5X/0lWfrf0QADHHhGd3QczcdCUpj911L3vg3W/sYYvuJTs3TUUkSUXxaccAS0qhxchrRYt66wiSpGLYL42aM6A8dTT+6k4aSknmPj48kzJs8qLjvd4Xgpue06DOdnLxAUHzM6+kDZ+HMZfJYuR+LtwGc2hgf5gsijff0ekUNXZiqATP7PF5mZxZ3Izoun1s4zG4LUMnvw2r+KqCKIw+3IQH03v+BCA9nMELNqbSf6tiWSrXJB3LAVGUcallcrw8V2t9EL4EhzJWrQUax5wLVMNS0+rUPA3k22Ncx4XXZS9o0MBH27Bo6BpNelZpS+/uh9KsNlY6bHCmJU9p8g7m3fVKn28H3KDYA5Pl/T8Z1ptDAVe0lXdQ2YoyyH2uyPIGHBZZIs2pDBS8R07+qN+E7Q==";
function verifyUrl(msgSignature, timestamp, nonce, echostr) {
    let signature = sha1(token, timestamp, nonce, echostr);
    if (msgSignature !== signature) {
        throw 'sign签名错误'
    }
    let aesKey = base64.toByteArray(encodingAesKey + "=");
    let replyEchoStr = decrypt(aesKey, echostr, receiveId);
    return replyEchoStr;
}

function aesDecrypt(aesKey, text) {
    const aesCbc = new aesJs.ModeOfOperation.cbc(
        [...aesKey],
        [...aesKey.slice(0, 16)]
    );
    return aesCbc.decrypt(text);
}
function decode(decrypted) {
    if (!decrypted) {
        return decrypted;
    }
    if (!Array.isArray(decrypted) && !decrypted.buffer) {
        throw new Error("参数必须是数组");
    }
    let pad = decrypted.slice(decrypted.byteLength - 1);
    if (pad < 1 || pad > BLOCK_SIZE) {
        pad = 0;
    }
    return decrypted.slice(0, decrypted.byteLength - pad);
}

function ntohl(x) {
    let sourceNumber = 0;
    (x || []).forEach(e => {
        sourceNumber <<= 8;
        sourceNumber |= e & 0xff;
    });
    return sourceNumber;
}

function decrypt(aesKey, text, receiveId) {
    let plainText = decode(
        aesDecrypt(aesKey, [...Buffer.from(text, "base64")])
    );
    let msgLen = ntohl([...plainText.slice(16, 20)]);
    let xmlContent = Buffer.from([
        ...plainText.slice(20, 20 + msgLen)
    ]).toString("utf8");
    let fromReceiveId = Buffer.from([...plainText.slice(20 + msgLen)]).toString(
        "utf8"
    );
    if (fromReceiveId !== receiveId) {
        throw '加密失败'
    }
    return xmlContent;
}

function sha1(token, timestamp, nonce, encrypt) {
    let sha1 = new jsSHA("SHA-1", "TEXT");
    sha1.update([token, timestamp, nonce, encrypt].sort().join(""));
    return sha1.getHash("HEX");
}
let result = verifyUrl(msg_signature, timestamp, nonce, echostr);
console.log(result)