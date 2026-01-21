const fs = require('fs');
const key = fs.readFileSync('./zap-shift-bd-b5b33-firebase-adminsdk-fbsvc-61c8ecdb86.json', 'utf8')
const base64 = Buffer.from(key).toString('base64')
console.log(base64)