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
package be.atbash.mp.auth.authenticator;

import be.atbash.ee.security.octopus.jwt.InvalidJWTException;
import be.atbash.ee.security.octopus.jwt.keys.JWKManagerKeySelector;
import be.atbash.mp.auth.jaspic.common.authmodules.TokenAuthenticator;
import be.atbash.mp.auth.validation.IssuerValidation;
import be.atbash.mp.auth.validation.MPJWTClaimSetValidation;
import be.atbash.util.StringUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 */
@RequestScoped
public class MPJWTTokenAuthenticator implements TokenAuthenticator {

    @Inject
    private JWKManagerKeySelector keySelector;

    @Inject
    private MPJWTClaimSetValidation claimSetValidation;

    @Inject
    private IssuerValidation issuerValidation;

    private String userName;

    private Set<String> roles;

    private Map<String, Object> claims;

    @Override
    public String getUserName() {
        return userName;
    }

    @Override
    public Set<String> getApplicationRoles() {
        return roles;
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    @Override
    public boolean authenticate(String token) {

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            validateSigning(signedJWT);

            if (claimSetValidation.isValid(signedJWT.getHeader(), signedJWT.getJWTClaimsSet(), issuerValidation)) {
                userName = defineUserName(signedJWT.getJWTClaimsSet());
                roles = new HashSet<>(signedJWT.getJWTClaimsSet().getStringListClaim("groups"));
                claims = signedJWT.getJWTClaimsSet().getClaims();
            }

        } catch (ParseException e) {
            e.printStackTrace();
        }

        return true;
    }

    private String defineUserName(JWTClaimsSet claimsSet) {
        String result = claimsSet.getClaim("upn").toString();  // We know from the validation it is a String, but by using getClaim we avoid ParseException.
        if (StringUtils.isEmpty(result)) {
            result = claimsSet.getClaim("preferred_username").toString();  // We know from the validation it is a String, but by using getClaim we avoid ParseException.
        }
        if (StringUtils.isEmpty(result)) {
            result = claimsSet.getSubject();
        }
        return result;
    }

    private void validateSigning(SignedJWT signedJWT) {
        String keyID = signedJWT.getHeader().getKeyID();
        Key key = keySelector.selectSecretKey(keyID);
        if (key == null) {
            throw new InvalidJWTException(String.format("No key found for %s", keyID));
        }

        RSAPublicKey rsaPublicKey = (RSAPublicKey) key;
        JWSVerifier jwsVerifier = new RSASSAVerifier(rsaPublicKey);

        try {
            if (!signedJWT.verify(jwsVerifier)) {
                throw new InvalidJWTException("JWT Signature verification failed");
            }
        } catch (JOSEException e) {
            throw new InvalidJWTException("JWT Signature verification failed");
        }
    }

}
