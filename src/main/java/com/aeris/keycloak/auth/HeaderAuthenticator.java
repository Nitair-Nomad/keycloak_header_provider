package com.aeris.keycloak.auth;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.OtherName;
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
        String certPem = context.getHttpRequest().getHttpHeaders()
                                .getHeaderString(HEADER_NAME);
        if (certPem == null || certPem.isEmpty()) {
            logger.debugf("Header '%s' not found.", HEADER_NAME);
            context.attempted();
            return;
        }
        try {
            String sanitized = certPem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\s+", "");
            byte[] certBytes = Base64.getDecoder().decode(sanitized);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf
                .generateCertificate(new ByteArrayInputStream(certBytes));

            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> entry : altNames) {
                    Integer type = (Integer) entry.get(0);
                    Object val = entry.get(1);
                    if (type == GeneralName.otherName && val instanceof byte[] derBytes) {
                        ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(derBytes);
                        OtherName other = OtherName.getInstance(seq);
                        ASN1Encodable tagVal = other.getValue();

                        // Tagged explicit or OctetString
                        ASN1Primitive prim;
                        if (tagVal instanceof ASN1TaggedObject) {
                            ASN1TaggedObject tagged = (ASN1TaggedObject) tagVal;
                            ASN1Encodable inner = tagged.getObject();
                            if (inner instanceof ASN1OctetString) {
                                prim = ASN1Primitive.fromByteArray(
                                    ((ASN1OctetString) inner).getOctets()
                                );
                            } else {
                                prim = inner.toASN1Primitive();
                            }
                        } else if (tagVal instanceof ASN1OctetString) {
                            prim = ASN1Primitive.fromByteArray(
                                ((ASN1OctetString) tagVal).getOctets()
                            );
                        } else {
                            prim = tagVal.toASN1Primitive();
                        }

                        if (prim instanceof ASN1String) {
                            String principalName = ((ASN1String) prim).getString();
                            logger.debugf("Extracted principalName: %s", principalName);
                            UserModel user = context.getSession().users()
                                .searchForUserByUserAttributeStream(
                                    context.getRealm(), 
                                    "PrincipalName", 
                                    principalName
                                ).findFirst().orElse(null);
                            if (user != null) {
                                context.setUser(user);
                                context.success();
                            } else {
                                logger.warnf("No user for PrincipalName '%s'", principalName);
                                context.attempted();
                            }
                            return;
                        }
                    }
                }
            }
            logger.warn("No principalName in otherName SAN");
            context.attempted();
        } catch (Exception e) {
            logger.error("Error parsing client certificate", e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}