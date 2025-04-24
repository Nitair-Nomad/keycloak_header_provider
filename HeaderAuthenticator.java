package com.aeris.keycloak.auth;

import jakarta.ws.rs.core.HttpHeaders;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.UserModel;
import org.keycloak.authentication.AuthenticationFlowError;

public class HeaderAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(HeaderAuthenticator.class);
    private static final String HEADER_NAME = "X-Principal-Name";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        String principalName = headers.getHeaderString(HEADER_NAME);

        logger.infof("Received header %s: %s", HEADER_NAME, principalName);

        if (principalName != null && !principalName.trim().isEmpty()) {
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), principalName);
            if (user != null) {
                context.setUser(user);
                context.success();
                logger.infof("Authentication successful for user: %s", principalName);
                return;
            } else {
                logger.warnf("User not found: %s", principalName);
            }
        } else {
            logger.warn("Missing or empty principal header.");
        }

        context.failure(AuthenticationFlowError.INVALID_USER);
    }

    @Override
    public void action(AuthenticationFlowContext context) {}

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
