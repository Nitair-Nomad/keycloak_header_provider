package com.aeris.keycloak.auth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.KeycloakSession;

import javax.ws.rs.core.HttpHeaders;
import java.util.List;
import java.util.stream.Collectors;

public class HeaderAuthenticator implements Authenticator {
    private static final Logger log = Logger.getLogger(HeaderAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String headerName = context.getAuthenticatorConfig().getConfig()
            .getOrDefault("header.name", "X-User-Principal");
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        String principalName = headers.getHeaderString(headerName);
        if (principalName == null || principalName.isEmpty()) {
            log.warnf("Header [%s] missing or empty", headerName);
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }
        String userAttr = context.getAuthenticatorConfig().getConfig()
            .getOrDefault("user.attribute", "PrincipalName");
        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        List<UserModel> matches = session.users().getUsersStream(realm)
            .filter(u -> principalName.equals(u.getFirstAttribute(userAttr)))
            .collect(Collectors.toList());
        if (matches.isEmpty()) {
            log.warnf("No user with %s=%s", userAttr, principalName);
            context.failure(AuthenticationFlowError.INVALID_USER);
            return;
        }
        context.setUser(matches.get(0));
        context.success();
    }

    @Override public void action(AuthenticationFlowContext context) { context.attempted(); }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
