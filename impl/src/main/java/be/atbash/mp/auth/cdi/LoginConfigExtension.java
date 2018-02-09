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
package be.atbash.mp.auth.cdi;

import be.atbash.util.exception.AtbashUnexpectedException;
import org.eclipse.microprofile.auth.LoginConfig;
import org.reflections.Reflections;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;

/**
 *
 */

public class LoginConfigExtension implements Extension {

    private String authMethod;

    private String path;

    public void observeBeforeBeanDiscovery(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        Reflections reflections = new Reflections("");
        Set<Class<? extends Application>> applicationClasses = reflections.getSubTypesOf(Application.class);

        Annotation[] annotations = applicationClasses.iterator().next().getAnnotations();
        for (Annotation annotation : annotations) {
            if (LoginConfig.class.getName().equals(annotation.annotationType().getName())) {
                authMethod = getMemberValue(annotation, "authMethod");
            }
            if (ApplicationPath.class.getName().equals(annotation.annotationType().getName())) {
                path = getMemberValue(annotation, "value");
            }
        }

    }

    private String getMemberValue(Annotation annotation, String member) {
        String result = null;
        for (Method method : annotation.annotationType().getDeclaredMethods()) {
            if (member.equals(method.getName())) {
                try {
                    Object authMethod = method.invoke(annotation);
                    result = authMethod.toString();
                } catch (IllegalAccessException | InvocationTargetException e) {
                    throw new AtbashUnexpectedException(e);
                }
            }
        }
        return result;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public String getPath() {
        return path;
    }
}
