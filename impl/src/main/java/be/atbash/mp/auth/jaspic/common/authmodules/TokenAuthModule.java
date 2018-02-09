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
package be.atbash.mp.auth.jaspic.common.authmodules;

import be.atbash.mp.auth.cdi.LoginConfigExtension;
import be.atbash.mp.auth.jaspic.common.core.HttpMsgContext;
import be.atbash.mp.auth.jaspic.common.core.HttpServerAuthModule;
import be.atbash.util.CDIUtils;
import be.atbash.util.StringUtils;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.regex.Pattern.compile;

/**
 * Authentication module that authenticates based on a token in the request.
 * <p>
 * <p>
 * Token to username/roles mapping is delegated to an implementation of {@link TokenAuthenticator}, which
 * should be registered as CDI bean.
 * <p>
 * Code modified from OmniSecurity https://github.com/omnifaces/omnisecurity.
 */
public class TokenAuthModule extends HttpServerAuthModule {

    private final static Pattern tokenPattern = compile("Bearer (.*)");

    private LoginConfigExtension loginConfigExtension;

    public TokenAuthModule() {
        loginConfigExtension = CDIUtils.retrieveInstance(LoginConfigExtension.class);
    }

    @Override
    public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {

        boolean microProfileJWTAuthrequired = false;
        if ("MP-JWT".equals(loginConfigExtension.getAuthMethod())) {
            microProfileJWTAuthrequired = request.getServletPath().startsWith(loginConfigExtension.getPath());
        }
        if (!microProfileJWTAuthrequired) {
            // FIXME What should we do when we receive request not for Jax-RS endpoint protected with MP-JWT method?
            return AuthStatus.SEND_FAILURE;
        }
        String token = getToken(request);
        if (StringUtils.hasText(token)) {

            // If a token is present, authenticate with it whether this is strictly required or not.

            TokenAuthenticator tokenAuthenticator = CDIUtils.retrieveInstance(TokenAuthenticator.class);
            if (tokenAuthenticator != null) {

                if (tokenAuthenticator.authenticate(token)) {
                    return httpMsgContext.notifyContainerAboutLogin(tokenAuthenticator.getUserName(), tokenAuthenticator.getClaims(), tokenAuthenticator.getApplicationRoles());
                }
            }
        }

        if (httpMsgContext.isProtected()) {
            return httpMsgContext.responseUnAuthorized();
        }

        return httpMsgContext.doNothing();
    }

    private String getToken(HttpServletRequest request) {

        String authorizationHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authorizationHeader)) {

            Matcher tokenMatcher = tokenPattern.matcher(authorizationHeader);

            if (tokenMatcher.matches()) {
                return tokenMatcher.group(1);
            }
        }

        return null;
    }

}