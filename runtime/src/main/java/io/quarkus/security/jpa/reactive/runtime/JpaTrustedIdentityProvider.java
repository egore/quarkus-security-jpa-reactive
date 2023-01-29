package io.quarkus.security.jpa.reactive.runtime;

import jakarta.inject.Inject;

import org.hibernate.FlushMode;
import org.hibernate.reactive.mutiny.Mutiny;
import org.jboss.logging.Logger;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TrustedAuthenticationRequest;
import io.smallrye.mutiny.Uni;

public abstract class JpaTrustedIdentityProvider extends AbstractJpaIdentityProvider
        implements IdentityProvider<TrustedAuthenticationRequest> {

    private static Logger log = Logger.getLogger(JpaTrustedIdentityProvider.class);

    @Inject
    Mutiny.SessionFactory sf;

    @Override
    public Class<TrustedAuthenticationRequest> getRequestType() {
        return TrustedAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(TrustedAuthenticationRequest request,
            AuthenticationRequestContext context) {
        return sf.withTransaction(session -> {
            session.setFlushMode(FlushMode.MANUAL);
            session.setDefaultReadOnly(true);
            try {
                return authenticate(session, request);
            } catch (SecurityException e) {
                log.debug("Authentication failed", e);
                throw new AuthenticationFailedException();
            }
        });
    }

    public abstract Uni<SecurityIdentity> authenticate(Mutiny.Session session,
            TrustedAuthenticationRequest request);
}
