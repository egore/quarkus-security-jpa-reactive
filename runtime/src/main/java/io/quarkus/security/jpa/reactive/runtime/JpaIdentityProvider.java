package io.quarkus.security.jpa.reactive.runtime;

import jakarta.inject.Inject;

import org.hibernate.FlushMode;
import org.hibernate.reactive.mutiny.Mutiny;
import org.jboss.logging.Logger;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.smallrye.mutiny.Uni;

public abstract class JpaIdentityProvider extends AbstractJpaIdentityProvider
        implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

    private static Logger log = Logger.getLogger(JpaIdentityProvider.class);

    @Inject
    Mutiny.SessionFactory sf;

    @Override
    public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
        return UsernamePasswordAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest request,
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
            UsernamePasswordAuthenticationRequest request);

}
