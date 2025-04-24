# Keycloak CAC Integration (Podman Deployment)

This package enables Common Access Card (CAC) login support with Keycloak behind an Apache reverse proxy. It assumes you have a working Keycloak + Apache setup and want to inject `X-Principal-Name` from CAC certs.

---

## Steps to Integrate

### 1. Copy Files
- Mount or COPY `extract-principal.sh` into your Apache container:
```Dockerfile
COPY extract-principal.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/extract-principal.sh
```

### 2. Update Apache Config
- Add contents of `apache-cac.conf` into your `httpd.conf` or a `.conf` in `conf.d/`
- Make sure `mod_ext_filter` is enabled.

### 3. Keycloak SPI
- Place the `HeaderAuthenticator.java` and `HeaderAuthenticatorFactory.java` into your custom Keycloak provider source tree.
- Make sure the `META-INF/services` file is present so Keycloak registers your provider.
- Rebuild and deploy your JAR.

### 4. Authentication Flow
- In Keycloak Admin Console:
  1. Create a new **authentication flow**
  2. Add your new **“Header Authenticator”** (ID: `header-authenticator`)
  3. Follow with Username/Password as fallback

### 5. Podman Networking
Ensure Apache and Keycloak are in the same network:
```bash
podman network create keycloak-net
podman run --network keycloak-net ...
```

---

## Security Notes
- Temporary certs are securely deleted
- `X-Principal-Name` is extracted from SAN, not the full cert
- Logging is minimal and does not expose certs
