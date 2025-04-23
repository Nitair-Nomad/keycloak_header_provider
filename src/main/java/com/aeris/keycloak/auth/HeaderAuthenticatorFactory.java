package com.aeris.keycloak.auth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class HeaderAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "header-authenticator";

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Header Authenticator (PrincipalName)"; }
    @Override public String getHelpText() {
        return "Parses X.509 otherName SAN for principalName and authenticates.";
    }
    @Override public Authenticator create(KeycloakSession session) {
        return new HeaderAuthenticator();
    }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }
    @Override public String getReferenceCategory() { return ID; }
}