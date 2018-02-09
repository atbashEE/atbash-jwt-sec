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
package be.atbash.mp.auth;

import org.eclipse.microprofile.jwt.AbstractJsonWebToken;

import java.util.Map;
import java.util.Set;

/**
 *
 */

public class AtbashJWTPrincipal extends AbstractJsonWebToken {

    private String name;
    private Map<String, Object> claims;

    public AtbashJWTPrincipal(String name, Map<String, Object> claims) {
        this.name = name;
        this.claims = claims;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Set<String> getClaimNames() {
        return claims.keySet();
    }

    @Override
    public <T> T getClaim(String claimName) {
        return (T) claims.get(claimName);
    }
}
