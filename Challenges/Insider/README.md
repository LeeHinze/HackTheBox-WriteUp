# Insider

## Challenge summary

**Insider** is a Hack The Box forensic challenge centered on a recovered
Mozilla Firefox profile. A potential insider threat has been reported, and our
goal is to determine what the user accessed.

The evidence includes the browser history, cookies, session data, and Firefox's
encrypted credential store. The key to solving the challenge is recognizing
that the profile contains everything required to decrypt a saved login.

## Inspecting the evidence

The supplied archive contains a `Mozilla` directory with a complete Firefox
profile. We begin by listing its files:

```bash
find Mozilla -type f
```

Among the many cache, telemetry, and configuration files, several artifacts
stand out:

```text
Mozilla/Firefox/Profiles/2542z9mo.default-release/logins.json
Mozilla/Firefox/Profiles/2542z9mo.default-release/key4.db
Mozilla/Firefox/Profiles/2542z9mo.default-release/places.sqlite
Mozilla/Firefox/Profiles/2542z9mo.default-release/cookies.sqlite
Mozilla/Firefox/Profiles/2542z9mo.default-release/formhistory.sqlite
```

`places.sqlite` normally contains browsing history and bookmarks, while
`cookies.sqlite` and `formhistory.sqlite` may reveal authenticated sessions or
previously submitted values. In this case, however, the most relevant file is
`logins.json`, Firefox's saved-login database.

## Finding the saved login

We can format `logins.json` with `jq`:

```bash
jq . Mozilla/Firefox/Profiles/2542z9mo.default-release/logins.json
```

The file contains one saved entry:

```json
{
  "hostname": "http://acc01:8080",
  "httpRealm": "Tomcat Manager Application",
  "encryptedUsername": "MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECF+d3kuwB9ZWBAj5QRmuUB+gqg==",
  "encryptedPassword": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECBqsTKru3+k8BBgCXKb5CRSS4SF6O3Dh4jUKFRBtxfiabQk=",
  "encType": 1,
  "timesUsed": 1
}
```

This shows that the user accessed a Tomcat Manager instance at
`http://acc01:8080`. The username and password are present, but Firefox stores
them in encrypted form.

## Understanding Firefox credential storage

Firefox separates saved-login data across two important files:

- `logins.json` stores the encrypted usernames and passwords together with
  metadata such as the target hostname.
- `key4.db` stores the key material used by Mozilla's Network Security Services
  library to protect those values.

Because both files come from the same browser profile, the credentials can be
recovered locally. We do not need to crack the encryption or attack the Tomcat
service.

Opening `key4.db` with SQLite confirms that it contains the expected NSS
tables:

```bash
sqlite3 Mozilla/Firefox/Profiles/2542z9mo.default-release/key4.db
```

```sql
.tables
```

```text
metaData    nssPrivate
```

The values in these tables are binary cryptographic data, so printing them
directly does not provide anything readable. They need to be processed using
Firefox's key-derivation and decryption scheme.

## Decrypting the credentials

[`firepwd`](https://github.com/lclevy/firepwd) is an open-source tool that can
parse `key4.db` and decrypt entries from `logins.json`. We clone the repository
and point it at the recovered Firefox profile:

```bash
git clone https://github.com/lclevy/firepwd.git
python3 firepwd/firepwd.py \
  -d Mozilla/Firefox/Profiles/2542z9mo.default-release/
```

The tool validates the password-check value, derives the profile key, and then
decrypts the saved username/password pair. The relevant line of output is:

```text
http://acc01:8080:b'admin',b'HTB{ur_8RoW53R_H157Ory}'
```

This confirms that the saved login belonged to the `admin` account for the
Tomcat Manager application. The decrypted password is the challenge flag.

## Flag

```text
HTB{ur_8RoW53R_H157Ory}
```

## Takeaway

A browser profile can contain far more than browsing history. When
`logins.json` and `key4.db` are recovered together, saved Firefox credentials
may be decrypted without interacting with the original system or remote
service. In this challenge, that credential record both identifies the
accessed application and reveals the flag.
