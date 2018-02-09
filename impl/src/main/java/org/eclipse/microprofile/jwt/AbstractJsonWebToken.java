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

import java.util.Set;

/**
 * default methods from the JsonWebToken class in the original API moved into this Abstract class.
 */
public abstract class AbstractJsonWebToken implements JsonWebToken {

    @Override
    public String getRawToken() {
        return getClaim(Claims.raw_token.name());
    }

    @Override
    public String getIssuer() {
        return getClaim(Claims.iss.name());
    }

    @Override
    public Set<String> getAudience() {
        return getClaim(Claims.aud.name());
    }

    @Override
    public String getSubject() {
        return getClaim(Claims.sub.name());
    }

    @Override
    public String getTokenID() {
        return getClaim(Claims.jti.name());
    }

    @Override
    public long getExpirationTime() {
        return getClaim(Claims.exp.name());
    }

    @Override
    public long getIssuedAtTime() {
        return getClaim(Claims.iat.name());
    }

    @Override
    public Set<String> getGroups() {
        return getClaim(Claims.groups.name());
    }

    @Override
    public boolean containsClaim(String claimName) {
        return getClaim(claimName) != null;
    }

    @Override
    public <T> T claim(String claimName) {
        return getClaim(claimName);
    }

}
