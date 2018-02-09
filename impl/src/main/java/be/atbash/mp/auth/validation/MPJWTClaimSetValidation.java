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
package be.atbash.mp.auth.validation;

import be.atbash.util.StringUtils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;

import javax.enterprise.context.ApplicationScoped;
import java.text.ParseException;
import java.util.Date;

import static com.nimbusds.jose.JOSEObjectType.JWT;

/**
 *
 */
@ApplicationScoped
public class MPJWTClaimSetValidation {

    private static final JWSAlgorithm RS_256 = new JWSAlgorithm("RS256");

    public boolean isValid(JWSHeader header, JWTClaimsSet claimsSet, IssuerValidation issuerValidation) {
        if (!header.getAlgorithm().equals(RS_256)) {
            return false;
        }
        if (!header.getType().equals(JWT)) {
            return false;
        }

        Date now = new Date();
        if (claimsSet.getExpirationTime() == null || !now.before(claimsSet.getExpirationTime())) {
            return false; // TODO Support clockSkew.
        }

        try {
            if (StringUtils.isEmpty(claimsSet.getStringClaim("upn"))
                    && StringUtils.isEmpty(claimsSet.getStringClaim("preferred_username"))
                    && StringUtils.isEmpty(claimsSet.getSubject())) {
                return false;
            }
        } catch (ParseException e) {
            return false;  // upn or preferred_username is not a String
        }

        return issuerValidation.isValid(header.getKeyID(), claimsSet.getIssuer());
    }
}
