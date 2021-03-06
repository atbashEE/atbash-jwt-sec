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
package be.atbash.mp.auth.jaspic.common.factory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import java.util.Map;

/**
 * This class functions as a kind of factory for {@link ServerAuthContext} instances, which are delegates for the actual
 * {@link ServerAuthModule} (SAM) that we're after.
 * <p>
 * Code OmniSecurity https://github.com/omnifaces/omnisecurity.
 */
public class TestServerAuthConfig implements ServerAuthConfig {

    private String layer;
    private String appContext;
    private CallbackHandler handler;
    private ServerAuthModule serverAuthModule;

    public TestServerAuthConfig(String layer, String appContext, CallbackHandler handler, ServerAuthModule serverAuthModule) {
        this.layer = layer;
        this.appContext = appContext;
        this.handler = handler;
        this.serverAuthModule = serverAuthModule;
    }

    @Override
    public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject,
                                            @SuppressWarnings("rawtypes") Map properties) throws AuthException {
        return new TestServerAuthContext(handler, serverAuthModule);
    }

    // ### The methods below mostly just return what has been passed into the
    // constructor.
    // ### In practice they don't seem to be called

    @Override
    public String getMessageLayer() {
        return layer;
    }

    /**
     * It's not entirely clear what the difference is between the "application context identifier" (appContext) and the
     * "authentication context identifier" (authContext). In early iterations of the specification, authContext was called
     * "operation" and instead of the MessageInfo it was obtained by something called an "authParam".
     */
    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return appContext;
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    @Override
    public void refresh() {
    }

    @Override
    public boolean isProtected() {
        return false;
    }

}
