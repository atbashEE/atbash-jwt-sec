# atbash-jwt-sec
Atbash implementation of MicroProfile JWT Auth Spec

## Prerequisites

* Java 7
* Java EE 7 (CDI 1.1, JASPIC 1.1, JAX-RS 2.0, EJB 3.x)

## Goal

Support MicroProfile JWT Auth token within Java EE 7 Rest style applications.

## Status

Partial implementation of the MicroProfile JWT Auth Spec.

Tested on WildFly 10.1

### Done

* Use MicroProfile JWT Auth token for populating Principal info of Java EE System
* Detection of @LoginConfig
* Use of @RolesAllowed

### TODO

* Injection of JWT claims

### Issues

* Status 500 when user has not the correct role (instead of status 4xx)
* Authentication for non JAX-RS URLs (in combination with the JWT Auth) 