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

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 */

//javax.security.auth.login.LoginException: unable to find LoginModule class: org.wildfly.swarm.mpjwtauth.deployment.auth.jaas.JWTLoginModule

public class Test {

    public static void main(String[] args) throws Exception {

        //ebcf1866-4751-4529-842b-821a38c5d945
        String token = TokenUtils.generateTokenString("/Token1.json", "ebcf1866-4751-4529-842b-821a38c5d945");

        System.out.println(token);

        String uri = "http://localhost:8080/demo/data/hello";
        WebTarget target = ClientBuilder.newClient()
                .target(uri);
        Response response = target.request(MediaType.TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer " + token).get();
        //Response response = target.request(MediaType.TEXT_PLAIN).get();
        System.out.println(response.getStatus());
        System.out.println(response.readEntity(String.class));

    }

}
