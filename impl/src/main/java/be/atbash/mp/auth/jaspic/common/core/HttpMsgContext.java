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
package be.atbash.mp.auth.jaspic.common.core;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

/**
 * A convenience context that provides access to JASPIC Servlet Profile specific types
 * and functionality.
 * <p>
 * Code OmniSecurity https://github.com/omnifaces/omnisecurity.
 */
public class HttpMsgContext {

    private CallbackHandler handler;
    private MessageInfo messageInfo;
    private Subject clientSubject;

    public HttpMsgContext(CallbackHandler handler, MessageInfo messageInfo, Subject clientSubject) {
        this.handler = handler;
        this.messageInfo = messageInfo;
        this.clientSubject = clientSubject;
    }

    /**
     * Checks if the current request is to a protected resource or not. A protected resource
     * is a resource (e.g. a Servlet, JSF page, JSP page etc) for which a constraint has been defined
     * in e.g. <code>web.xml<code>.
     *
     * @return true if a protected resource was requested, false if a public resource was requested.
     */
    public boolean isProtected() {
        return Jaspic.isProtectedResource(messageInfo);
    }

    public void cleanClientSubject() {
        Jaspic.cleanSubject(clientSubject);
    }

    /**
     * Returns the request object associated with the current request.
     *
     * @return the request object associated with the current request.
     */
    public HttpServletRequest getRequest() {
        return (HttpServletRequest) messageInfo.getRequestMessage();
    }

    /**
     * Returns the response object associated with the current request.
     *
     * @return the response object associated with the current request.
     */
    public HttpServletResponse getResponse() {
        return (HttpServletResponse) messageInfo.getResponseMessage();
    }

    /**
     * Sets the response status to 401 (not found).
     * <p>
     * As a convenience this method returns SEND_FAILURE, so this method can be used in
     * one fluent return statement from an auth module.
     *
     * @return {@link AuthStatus#SEND_FAILURE}
     */
    public AuthStatus responseUnAuthorized() {
        try {
            getResponse().sendError(SC_UNAUTHORIZED);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }

        return SEND_FAILURE;
    }

    /**
     * Asks the container to register the given username and roles in order to make
     * them available to the application for use with {@link HttpServletRequest#isUserInRole(String)} etc.
     * <p>
     * <p>
     * Note that after this call returned, the authenticated identity will not be immediately active. This
     * will only take place (should not errors occur) after the {@link ServerAuthContext} or {@link ServerAuthModule}
     * in which this call takes place return control back to the runtime.
     * <p>
     * <p>
     * As a convenience this method returns SUCCESS, so this method can be used in
     * one fluent return statement from an auth module.
     *
     * @param username the user name that will become the caller principal
     * @param roles    the roles associated with the caller principal
     * @return {@link AuthStatus#SUCCESS}
     */
    public AuthStatus notifyContainerAboutLogin(String username, Map<String, Object> claims, Set<String> roles) {
        Jaspic.notifyContainerAboutLogin(clientSubject, handler, username, claims, roles);

        return SUCCESS;
    }

    /**
     * Instructs the container to "do nothing".
     * <p>
     * <p>
     * This is a somewhat peculiar requirement of JASPIC, which incidentally almost no containers actually require
     * or enforce.
     * <p>
     * <p>
     * When intending to do nothing, most JASPIC auth modules simply return "SUCCESS", but according to
     * the JASPIC spec the handler MUST have been used when returning that status. Because of this JASPIC
     * implicitly defines a "protocol" that must be followed in this case;
     * invoking the CallerPrincipalCallback handler with a null as the username.
     * <p>
     * <p>
     * As a convenience this method returns SUCCESS, so this method can be used in
     * one fluent return statement from an auth module.
     *
     * @return {@link AuthStatus#SUCCESS}
     */
    public AuthStatus doNothing() {
        Jaspic.notifyContainerAboutLogin(clientSubject, handler, null, null);

        return SUCCESS;
    }

}