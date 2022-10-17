const crypto = require('crypto');
const https = require('https');
const util=require('util')
var url = require('url');

const METALCLOUD_ENDPOINT = process.env.METALCLOUD_ENDPOINT;
const METALCLOUD_API_KEY = process.env.METALCLOUD_API_KEY;

if (!METALCLOUD_ENDPOINT) {
    console.error("METALCLOUD_ENDPOINT environment variable not set. The format should not include the /api/developer/developer and only the prefix, same as the CLI.");
    process.exit(1);
}

if (!METALCLOUD_API_KEY) {
    console.error("METALCLOUD_API_KEY environment variable not set.");
    process.exit(1);
}

const USER_ID = METALCLOUD_API_KEY.split(":")[0];

async function make_api_call(method, params = [], endpoint = METALCLOUD_ENDPOINT, api_key = METALCLOUD_API_KEY) {
    if (!endpoint || !api_key) {
        throw "endpoint or api_key parameters are required";
    }

    const data = JSON.stringify({id: 0, jsonrpc: "2.0", method: method, params: params})
    const path = `/api/developer/developer?verify=${api_key.split(":")[0]}:${crypto.createHmac('md5', api_key).update(data).digest('hex')}`;
    const options = { method: 'POST', host: url.parse(METALCLOUD_ENDPOINT).hostname, path: path };
    
    return new Promise(function(resolve, reject) {
        var req = https.request(options, function(res) {
            if (res.statusCode < 200 || res.statusCode >= 300) {
                return reject(new Error('statusCode=' + res.statusCode));
            }
            var body = [];
            res.on('data', function(chunk) { body.push(chunk); });
            res.on('end', function() {
                try {
                    body = JSON.parse(Buffer.concat(body).toString());
                } catch(e) {
                    reject(e);
                }
                resolve(body["result"]);
            });
        });
        req.on('error', function(err) { reject(err); });
        req.write(data);
        req.end();
    })
}

async function infrastructures(user_id) {
    return await make_api_call("infrastructures", [user_id]);
}

(async () => {
    console.log(JSON.stringify(await infrastructures(USER_ID)));
})();

