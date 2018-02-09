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
package be.atbash.mp.auth.test;

import be.atbash.config.exception.ConfigurationException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.eclipse.microprofile.jwt.Claims;

import java.io.InputStream;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Scanner;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

/**
 *
 */

public class TokenUtils {
    private TokenUtils() {
    }

    /**
     * Utility method to generate a JWT string from a JSON resource file that is signed by the private key within test.jwk
     * test resource key, possibly with invalid fields.
     *
     * @param jsonResName - name of test resources file
     * @param kid
     * @return the JWT string
     * @throws Exception on parse failure
     */
    public static String generateTokenString(String jsonResName, String kid) throws Exception {

        InputStream contentIS = TokenUtils.class.getResourceAsStream(jsonResName);
        byte[] tmp = new byte[4096];
        int length = contentIS.read(tmp);
        byte[] content = new byte[length];
        System.arraycopy(tmp, 0, content, 0, length);

        JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
        JSONObject jwtContent = (JSONObject) parser.parse(content);

        long currentTimeInSecs = currentTimeInSecs();
        long exp = currentTimeInSecs + 300;
        jwtContent.put(Claims.exp.name(), exp);

        jwtContent.put(Claims.iat.name(), currentTimeInSecs);
        jwtContent.put(Claims.auth_time.name(), currentTimeInSecs);

        // Use the test private key associated with the test public key for a valid signature
        PrivateKey pk = readPrivateKey();

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(pk);
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(jwtContent);
        JWSAlgorithm alg = JWSAlgorithm.RS256;

        JWSHeader jwtHeader = new JWSHeader.Builder(alg)
                .keyID(kid)
                .type(JOSEObjectType.JWT)
                .build();
        SignedJWT signedJWT = new SignedJWT(jwtHeader, claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    /**
     * Read a  private key from the jwk (classpath)
     *
     * @return PrivateKey
     * @throws Exception on decode failure
     */
    public static PrivateKey readPrivateKey() throws Exception {

        InputStream inputStream = TokenUtils.class.getClassLoader().getResourceAsStream("test.jwk");

        JWK result;
        try {
            String content = (new Scanner(inputStream)).useDelimiter("\\Z").next();
            result = JWK.parse(content);
        } catch (ParseException e) {
            throw new ConfigurationException(String.format("Parsing the JWK file failed with %s", e.getMessage()));
        }
        return ((RSAKey) result).toRSAPrivateKey();
    }

    /**
     * @return the current time in seconds since epoch
     */
    public static int currentTimeInSecs() {
        long currentTimeMS = System.currentTimeMillis();
        int currentTimeSec = (int) (currentTimeMS / 1000);
        return currentTimeSec;
    }

}
