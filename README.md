# Keycloak CAC Header Authenticator

This Keycloak custom authenticator plugin enables X.509 smart card (CAC) authentication by extracting the `principalName` (UPN) from the client's certificate and logging the user in by matching that value against a `principalName` user attribute in Keycloak.

## 🔧 Requirements

- Java 21+
- Apache Maven
- Keycloak 26.1+
- Apache HTTPD (used as TLS terminator and certificate validator)
- Podman + Quadlet (optional, for containerized deployments)

---

## 📦 Build Instructions

```bash
# Clone the repo
git clone https://github.com/your-org/keycloak-cac-auth.git
cd keycloak-cac-auth

# Set JAVA_HOME (if needed)
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk

# Build the JAR
mvn clean package -DskipTests
```

Output: `target/keycloak-header-authenticator.jar`

---

## 🧩 Keycloak Integration

### 📁 Option 1: Podman Mount

Update your `keycloak.container` Quadlet unit:

```ini
[Container]
Volumes=/full/path/to/target:/opt/keycloak/providers:ro
```

Reload systemd:

```bash
systemctl --user daemon-reload
systemctl --user restart keycloak.container
```

### ⚙️ Option 2: Manual Deployment (non-container)

Copy the JAR into your Keycloak install:

```bash
cp target/keycloak-header-authenticator.jar $KEYCLOAK_HOME/providers/
```

Restart Keycloak:

```bash
bin/kc.sh start-dev
```

---

## 🔐 Apache Configuration (TLS & CAC)

Apache terminates TLS and validates the client certificate:

```apache
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/server-cert.pem
    SSLCertificateKeyFile /etc/ssl/private/server-key.pem
    SSLCACertificateFile /etc/ssl/certs/dod_chain.pem

    SSLVerifyClient require
    SSLVerifyDepth 5

    RequestHeader unset SSL_CLIENT_CERT
    RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s"

    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
</VirtualHost>
```

---

## 🧠 Keycloak Flow Setup

1. Log into Admin Console
2. Go to `Authentication → Flows → New`
   - Name: `CAC PrincipalName`
   - Type: `Browser`
3. Add Execution:
   - Select: `com.aeris.keycloak.auth.HeaderAuthenticator`
   - Requirement: `REQUIRED`
4. Go to `Realm Settings → Authentication`
   - Set `Browser Flow` → `CAC PrincipalName`

---

## 👤 User Setup

For each user in Keycloak:

1. Go to `Users → [User] → Attributes`
2. Add:
   - Key: `principalName`
   - Value: `john.doe.1234567890@mil`

This must match the UPN/principalName in the CAC certificate.

---

## ✅ Done

Users will now authenticate using CAC with no password prompts. Apache verifies the cert; Keycloak extracts identity from the cert directly.

---

## 🛡 Hardening Suggestions

- Enforce client cert depth and CAs in Apache
- Disable traditional login forms if CAC is exclusive
- Set fallback timeout and logging in custom flow

---

## 🧾 License

MIT — Use freely, modify responsibly.