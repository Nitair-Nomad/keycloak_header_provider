package com.aeris.keycloak.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.*;
import org.keycloak.services.ServicesLogger;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public class HeaderAuthenticator implements Authenticator {

    private static final ServicesLogger logger = ServicesLogger.LOGGER;
    private static final String HEADER_NAME = "SSL_CLIENT_CERT";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String certPem = context.getHttpRequest().getHttpHeaders().getHeaderString(HEADER_NAME);

        if (certPem == null || certPem.isEmpty()) {
            logger.warnf("Header '%s' not found in request.", HEADER_NAME);
            context.attempted();
            return;
        }

        try {
            String sanitized = certPem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\s+", "");
            byte[] certBytes = Base64.getDecoder().decode(sanitized);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));

            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> altName : altNames) {
                    if (altName.size() < 2) continue;
                    Integer type = (Integer) altName.get(0);
                    Object value = altName.get(1);
                    if (type == 0 && value instanceof String) {
                        String principalName = (String) value;
                        UserModel user = context.getSession().users()
                                .searchForUserByUserAttributeStream(context.getRealm(), "principalName", principalName)
                                .findFirst().orElse(null);

                        if (user != null) {
                            context.setUser(user);
                            context.success();
                        } else {
                            logger.warnf("No user found with principalName '%s'", principalName);
                            context.failure(AuthenticationFlowError.UNKNOWN_USER);
                        }
                        return;
                    }
                }
            }

            logger.warn("No principalName found in certificate SAN");
            context.attempted();
        } catch (Exception e) {
            logger.error("Error processing client certificate", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {}

    @Override
    public boolean requiresUser() { return false; }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}