package io.quarkus.security.jpa.reactive;

import jakarta.inject.Singleton;

import org.hibernate.reactive.common.Identifier;
import org.hibernate.reactive.mutiny.Mutiny;
import org.wildfly.security.password.Password;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.jpa.reactive.runtime.JpaIdentityProvider;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

@Singleton
public class UserEntityIdentityProvider extends JpaIdentityProvider {

    @Override
    public Uni<SecurityIdentity> authenticate(Mutiny.Session session,
            UsernamePasswordAuthenticationRequest request) {

        String username = request.getUsername();
        return session.find(PlainUserEntity.class, Identifier.id("name", username))
                .map((PlainUserEntity user) -> {
                    if (user == null)
                        return null;

                    // for MCF:
                    //               Password storedPassword = getMcfPasword(user.pass);
                    // for clear:
                    Password storedPassword = getClearPassword(user.pass);

                    QuarkusSecurityIdentity.Builder builder = checkPassword(storedPassword, request);

                    addRoles(builder, user.role);
                    return builder.build();
                });
    }
}
