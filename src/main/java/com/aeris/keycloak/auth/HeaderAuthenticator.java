package com.aeris.keycloak.auth;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.UserModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSession;

public class HeaderAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        var principalHeader = headers.getRequestHeader("X-User-Principal");
        if (principalHeader != null && !principalHeader.isEmpty()) {
            String principal = principalHeader.get(0);
            UserModel user = context
                .getSession()
                .users()
                .getUserByUsername(context.getRealm(), principal);
            if (user != null) {
                context.setUser(user);
                context.success();
                return;
            }
        }

        context.failureChallenge(
            AuthenticationFlowError.INVALID_USER,
            context.form()
                   .setError("Invalid header principal")
                   .createErrorPage(Response.Status.UNAUTHORIZED)
        );
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}