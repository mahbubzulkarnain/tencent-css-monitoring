const crypto = require('crypto');

const REGION = 'ap-guangzhou';
const SERVICE = 'live';
const HOST = `${SERVICE}.tencentcloudapi.com`;
const VERSION = '2018-08-01';

const ALLOWED_ACTIONS = new Set([
  'DescribeGroupProIspPlayInfoList',
  'DescribeHttpStatusInfoList',
]);

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function buildAuthorization(secretId, secretKey, payloadStr, action, timestamp, date) {
  const canonicalHeaders = `content-type:application/json\nhost:${HOST}\nx-tc-action:${action.toLowerCase()}\n`;
  const signedHeaders = 'content-type;host;x-tc-action';
  const hashedPayload = sha256Hex(payloadStr);
  const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;

  const credentialScope = `${date}/${SERVICE}/tc3_request`;
  const hashedCanonical = sha256Hex(canonicalRequest);
  const stringToSign = `TC3-HMAC-SHA256\n${timestamp}\n${credentialScope}\n${hashedCanonical}`;

  const secretDate = hmac('TC3' + secretKey, date);
  const secretService = hmac(secretDate, SERVICE);
  const secretSigning = hmac(secretService, 'tc3_request');
  const signature = crypto.createHmac('sha256', secretSigning).update(stringToSign, 'utf8').digest('hex');

  return `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const { secretId, secretKey, action, payload } = req.body || {};

  if (!secretId || !secretKey) {
    res.status(400).json({ error: 'secretId dan secretKey wajib diisi.' });
    return;
  }

  if (!ALLOWED_ACTIONS.has(action)) {
    res.status(400).json({ error: `Action tidak diizinkan: ${action}` });
    return;
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().split('T')[0];
  const payloadStr = JSON.stringify(payload || {});
  const authorization = buildAuthorization(secretId, secretKey, payloadStr, action, timestamp, date);

  try {
    const tcRes = await fetch(`https://${HOST}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Host': HOST,
        'Authorization': authorization,
        'X-TC-Action': action,
        'X-TC-Region': REGION,
        'X-TC-Timestamp': String(timestamp),
        'X-TC-Version': VERSION,
      },
      body: payloadStr,
    });

    const json = await tcRes.json();
    res.status(200).json(json);
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
};
