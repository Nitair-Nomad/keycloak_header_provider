package com.aeris.keycloak.auth;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class HeaderAuthenticatorFactory implements ConfigurableAuthenticatorFactory {
    public static final String PROVIDER_ID = "header-authenticator";
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED,
        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
        AuthenticationExecutionModel.Requirement.DISABLED
    };
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    static {
        ProviderConfigProperty p = new ProviderConfigProperty();
        p.setName("header.name");
        p.setLabel("Header Name");
        p.setType(ProviderConfigProperty.STRING_TYPE);
        p.setHelpText("HTTP header name");
        p.setDefaultValue("X-User-Principal");
        configProperties.add(p);
        p = new ProviderConfigProperty();
        p.setName("user.attribute");
        p.setLabel("User Attribute");
        p.setType(ProviderConfigProperty.STRING_TYPE);
        p.setHelpText("Keycloak user attribute");
        p.setDefaultValue("PrincipalName");
        configProperties.add(p);
    }

    public String getId() { return PROVIDER_ID; }
    public String getDisplayType() { return "Header Authenticator"; }
    public String getReferenceCategory() { return "x509"; }
    public boolean isConfigurable() { return true; }
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    public boolean isUserSetupAllowed() { return false; }
    public String getHelpText() {
        return "Authenticates by matching an HTTP header to a user attribute.";
    }
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    public Authenticator create(KeycloakSession session) {
        return new HeaderAuthenticator();
    }
    public void close() {}
}
