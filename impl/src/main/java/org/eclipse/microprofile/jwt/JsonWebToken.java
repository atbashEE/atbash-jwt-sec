/*
 * Copyright 2018 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.eclipse.microprofile.jwt;

import java.security.Principal;
import java.util.Set;

/**
 * A read-only interface for the the claims required by Eclipse MicroProfile
 * conforming tokens. Additional information about the claims defined by OIDC
 * and RFC7519 can be found at https://www.iana.org/assignments/jwt/jwt.xhtml.
 * <p>
 * This is compatible with the pre-JSR 375 caller {@link Principal} api.
 * <p>
 * Code from microprofile-jwt-auth-api https://github.com/eclipse/microprofile-jwt-auth/api
 */
public interface JsonWebToken extends Principal {

    /**
     * Returns the unique name of this principal. This either comes from the upn
     * claim, or if that is missing, the preferred_username claim. Note that for
     * guaranteed interoperability a upn claim should be used.
     *
     * @return the unique name of this principal.
     */
    @Override
    String getName();

    /**
     * Get the raw bearer token string originally passed in the authentication
     * header
     *
     * @return raw bear token string
     */
    String getRawToken();

    /**
     * The iss(Issuer) claim identifies the principal that issued the JWT
     *
     * @return the iss claim.
     */
    String getIssuer();

    /**
     * The aud(Audience) claim identifies the recipients that the JWT is
     * intended for.
     *
     * @return the aud claim or null if the claim is not present
     */
    Set<String> getAudience();

    /**
     * The sub(Subject) claim identifies the principal that is the subject of
     * the JWT. This is the token issuing
     * IDP subject, not the
     *
     * @return the sub claim.
     */
    String getSubject();

    /**
     * The jti(JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.
     *
     * @return the jti claim.
     */
    String getTokenID();

    /**
     * The exp (Expiration time) claim identifies the expiration time on or
     * after which the JWT MUST NOT be accepted
     * for processing in seconds since 1970-01-01T00:00:00Z UTC
     *
     * @return the exp claim.
     */
    long getExpirationTime();

    /**
     * The iat(Issued at time) claim identifies the time at which the JWT was
     * issued in seconds since 1970-01-01T00:00:00Z UTC
     *
     * @return the iat claim
     */
    long getIssuedAtTime();

    /**
     * The groups claim provides the group names the JWT principal has been
     * granted.
     * <p>
     * This is a MicroProfile specific claim.
     *
     * @return a possibly empty set of group names.
     */
    Set<String> getGroups();

    /**
     * Access the names of all claims are associated with this token.
     *
     * @return non-standard claim names in the token
     */
    Set<String> getClaimNames();

    /**
     * Verify is a given claim exists
     *
     * @param claimName - the name of the claim
     * @return true if the JsonWebToken contains the claim, false otherwise
     */
    boolean containsClaim(String claimName);

    /**
     * Access the value of the indicated claim.
     *
     * @param claimName - the name of the claim
     * @return the value of the indicated claim if it exists, null otherwise.
     */
    <T> T getClaim(String claimName);

    /**
     * Original the method to return the claim wrapped within a {@code Optional}. Within Atbash it does the same thing as getClaim.
     *
     * @param claimName - the name of the claim
     * @param <T>       - the type of the claim value to return
     * @return an Optional wrapper of the claim value
     */
    <T> T claim(String claimName);
}
