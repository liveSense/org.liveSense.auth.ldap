/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.liveSense.auth.ldap;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.Value;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.PropertyOption;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.AuthUtil;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.base.util.AccessControlUtil;
import org.liveSense.auth.FormReason;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * The <code>LdapAuthenticationHandler</code> class implements the authorization
 * steps based on a cookie.
 */
@Component(label = "%auth.ldap.name", description = "%auth.ldap.description", metatype = true, name = "org.liveSense.auth.LdapAuthenticationHandler")
@Properties( {
	@Property(name = Constants.SERVICE_DESCRIPTION, value = "liveSense Ldap Based Authentication Handler"),
	@Property(name = Constants.SERVICE_VENDOR, value = "liveSense.org"),
	@Property(name = AuthenticationHandler.PATH_PROPERTY, value = "/", cardinality = 100),
	@Property(name = AuthenticationHandler.TYPE_PROPERTY, value = LdapAuthenticationHandler.LDAP_AUTH, propertyPrivate = true),
	@Property(name = Constants.SERVICE_RANKING, intValue = 0, propertyPrivate = false) })
@Service
public class LdapAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

	public static final String LDAP_AUTH = "Ldap";


	/**
	 * Ldap AuthInfo LdapUrl attribute name
	 */        
	private static final String PAR_LDAP_URL = "ldap.url";

	private static final String DEFAULT_LDAP_URL = "ldap://localhost:10389";

	@Property(name=PAR_LDAP_URL, value=DEFAULT_LDAP_URL)
	private String ldapUrl;


	/**
	 * Ldap AuthInfo LdapBase attribute name
	 */        
	private static final String PAR_LDAP_BASE = "ldap.base";

	private static final String DEFAULT_LDAP_BASE = "uid=${userName},ou=system";

	@Property(name=PAR_LDAP_BASE, value=DEFAULT_LDAP_BASE)
	private String ldapBase;

	/**
	 * Ldap AuthInfo Ldap Authentication type attribute name
	 */        
	private static final String PAR_LDAP_AUTHENTICATION_TYPE = "ldap.authentication_type";

	private static final String DEFAULT_LDAP_AUTHENTICATION_TYPE = "simple";

	@Property(name=PAR_LDAP_AUTHENTICATION_TYPE, value=DEFAULT_LDAP_AUTHENTICATION_TYPE)
	private String ldapAuthenticationType;


	/**
	 * The name of the parameter providing the login form URL.
	 */
	@Property(value=AuthenticationFormServlet.SERVLET_PATH)
	private static final String PAR_LOGIN_FORM = "ldap.login.form";

	/**
	 * The value of the {@link #PAR_AUTH_STORAGE} parameter indicating the use
	 * of a Cookie to store the authentication data.
	 */
	private static final String AUTH_STORAGE_COOKIE = "cookie";

	/**
	 * The value of the {@link #PAR_AUTH_STORAGE} parameter indicating the use
	 * of a session attribute to store the authentication data.
	 */
	private static final String AUTH_STORAGE_SESSION_ATTRIBUTE = "session";

	/**
	 * To be used to determine if the auth has value comes from a cookie or from
	 * a session attribute.
	 */
	private static final String DEFAULT_AUTH_STORAGE = AUTH_STORAGE_COOKIE;

	private static final String PAR_AUTH_STORAGE = "ldap.auth.storage";
	@Property(name=PAR_AUTH_STORAGE, value = DEFAULT_AUTH_STORAGE, options = {
			@PropertyOption(name = AUTH_STORAGE_COOKIE, value = "Cookie"),
			@PropertyOption(name = AUTH_STORAGE_SESSION_ATTRIBUTE, value = "Session Attribute") })
	private String authStorageType;

	/**
	 * The default Cookie or session attribute name
	 *
	 * @see #PAR_AUTH_NAME
	 */
	private static final String DEFAULT_AUTH_NAME = "sling.ldapauth";

	/**
	 * The name of the configuration parameter providing the Cookie or session
	 * attribute name.
	 */
	@Property(value = DEFAULT_AUTH_NAME)
	private static final String PAR_AUTH_NAME = "ldap.auth.name";

	/**
	 * Default value for the {@link #PAR_CREDENTIALS_ATTRIBUTE_NAME} property
	 */
	private static final String DEFAULT_CREDENTIALS_ATTRIBUTE_NAME = DEFAULT_AUTH_NAME;

	/**
	 * This is the name of the SimpleCredentials attribute that holds the auth
	 * info extracted from the cookie value.
	 */
	@Property(value = DEFAULT_CREDENTIALS_ATTRIBUTE_NAME)
	private static final String PAR_CREDENTIALS_ATTRIBUTE_NAME = "form.credentials.name";

	/**
	 * The default authentication data time out value.
	 *
	 * @see #PAR_AUTH_TIMEOUT
	 */
	private static final int DEFAULT_AUTH_TIMEOUT = 30;

	/**
	 * The number of minutes after which a login session times out. This value
	 * is used as the expiry time set in the authentication data.
	 */
	@Property(intValue = DEFAULT_AUTH_TIMEOUT)
	public static final String PAR_AUTH_TIMEOUT = "ldap.auth.timeout";

	private static final String DEFAULT_TOKEN_FILE = "cookie-tokens.bin";

	/**
	 * The name of the file used to persist the security tokens
	 */
	@Property(value = DEFAULT_TOKEN_FILE)
	private static final String PAR_TOKEN_FILE = "ldap.token.file";

	private static final boolean DEFAULT_TOKEN_FAST_SEED = false;

	/**
	 * Whether to use a less secure but faster seeding mechanism to seed the
	 * random number generator in the {@link TokenStore}. By default the faster
	 * mechanism is disabled and the platform provided seeding is used. This may
	 * however block the startup considerably, particularly on Linux and Solaris
	 * platforms which use the (blocking but secure) <code>/dev/random</code>
	 * device for seeding.
	 */
	@Property(boolValue = DEFAULT_TOKEN_FAST_SEED)
	private static final String PAR_TOKEN_FAST_SEED = "ldap.token.fastseed";

	/**
	 * The default include value.
	 *
	 * @see #PAR_INCLUDE_FORM
	 */
	private static final boolean DEFAULT_INCLUDE_FORM = false;

	/**
	 * Whether to redirect to the login form or simple do an include.
	 */
	@Property(boolValue = DEFAULT_INCLUDE_FORM)
	public static final String PAR_INCLUDE_FORM = "ldap.use.include";

	/**
	 * The default login after expire of a cookie.
	 *
	 * @see #PAR_LOGIN_AFTER_EXPIRE
	 */
	private static final boolean DEFAULT_LOGIN_AFTER_EXPIRE = false;

	/**
	 * Whether to present a login form when a users cookie expires, the default
	 * is not to present the form.
	 */
	@Property(boolValue = DEFAULT_LOGIN_AFTER_EXPIRE)
	private static final String PAR_LOGIN_AFTER_EXPIRE = "ldap.onexpire.login";

	/**
	 * The default domain on which to see the auth cookie (if cookie storage is used)
	 */
	@Property
	private static final String PAR_DEFAULT_COOKIE_DOMAIN = "ldap.default.cookie.domain";

	
	/**
	 * There is a field in JCR User's, the ldap.identity. The authentication
	 * first search for a user who have the property with the user name field value.
	 * If there is match, when the LDAP matches, the system uses that credential for authorization.
	 * When there  is no user with that identity, the user is creating with the given name when the LDAP authentication
	 * is successfull. It the user exists with same name, the ldap identity is set.
	 */
	private static final boolean DEFAULT_AUTOCREATE_JCR_USER = true;
	@Property(boolValue = DEFAULT_AUTOCREATE_JCR_USER)
	private static final String PAR_AUTOCREATE_JCR_USER = "ldap.jcr.user.autocreate";
	private boolean autoCreateJcrUser = DEFAULT_AUTOCREATE_JCR_USER;

	
	/**
	 * The LDAP can contains some properties for user for example credentials to access another system. When user logging
	 * in theese properties copied to JCR's user.
	 */
	private static final String[] DEFAULT_USER_ATTRIBUTES = new String[]{};
	@Property(value = {}, cardinality=Integer.MAX_VALUE)
	private static final String PAR_USER_ATTRIBUTES = "ldap.jcr.user.attributes";
	private String[] userAttributes = DEFAULT_USER_ATTRIBUTES;

	/**
	 * The request method required for user name and password submission by the
	 * form (value is "POST").
	 */
	private static final String REQUEST_METHOD = "POST";

	/**
	 * The last segment of the request URL for the user name and password
	 * submission by the form (value is "/j_security_check").
	 * <p>
	 * This name is derived from the prescription in the Servlet API 2.4
	 * Specification, Section SRV.12.5.3.1 Login Form Notes: <i>In order for the
	 * authentication to proceeed appropriately, the action of the login form
	 * must always be set to <code>j_security_check</code>.</i>
	 */
	private static final String REQUEST_URL_SUFFIX = "/j_security_check";

	/**
	 * The name of the form submission parameter providing the name of the user
	 * to authenticate (value is "j_username").
	 * <p>
	 * This name is prescribed by the Servlet API 2.4 Specification, Section
	 * SRV.12.5.3 Form Based Authentication.
	 */
	private static final String PAR_J_USERNAME = "j_username";

	/**
	 * The name of the form submission parameter providing the password of the
	 * user to authenticate (value is "j_password").
	 * <p>
	 * This name is prescribed by the Servlet API 2.4 Specification, Section
	 * SRV.12.5.3 Form Based Authentication.
	 */
	private static final String PAR_J_PASSWORD = "j_password";

	/**
	 * Key in the AuthenticationInfo map which contains the domain on which the
	 * auth cookie should be set.
	 */
	private static final String COOKIE_DOMAIN = "cookie.domain";

	/**
	 * The factor to convert minute numbers into milliseconds used internally
	 */
	private static final long MINUTES = 60L * 1000L;


	/**
	 * Ldap identifier property name in User Node. This property contains the Ldap name of user
	 */
	private static final String PAR_LDAP_ID_IDENTIFIER_PROPERTY = "ldap.property.identity";

	private static final String DEFAULT_LDAP_ID_IDENTIFIER_PROPERTY = "ldap.identity";

	@Property(name=PAR_LDAP_ID_IDENTIFIER_PROPERTY, value=DEFAULT_LDAP_ID_IDENTIFIER_PROPERTY)
	private String identityProperty;

	/**
	 * Ldap AuthInfo LdapUser attribute name
	 */        
	private static final String PAR_LDAP_USER_ATTR = "ldap.user.attr";

	private static final String DEFAULT_LDAP_USER_ATTR = "ldap.user";

	@Property(name=PAR_LDAP_USER_ATTR, value=DEFAULT_LDAP_USER_ATTR)
	private String attrLdapId;



	/** default log */
	private final Logger log = LoggerFactory.getLogger(getClass());

	private AuthenticationStorage authStorage;

	private String loginForm;

	/**
	 * The timeout of a login session in milliseconds, converted from the
	 * configuration property {@link #PAR_AUTH_TIMEOUT} by multiplying with
	 * {@link #MINUTES}.
	 */
	private long sessionTimeout;

	/**
	 * The name of the credentials attribute which is set to the cookie data
	 * to validate.
	 */
	private String attrCookieAuthData;

	/**
	 * The {@link TokenStore} used to persist and check authentication data
	 */
	private TokenStore tokenStore;

	/**
	 * The {@link FormLoginModulePlugin} service registration created when
	 * this authentication handler is registered. If the login module plugin
	 * cannot be created this field is set to <code>null</code>.
	 */
	private ServiceRegistration loginModule;

	/**
	 * If true, the handler will attempt to include the login form instead of
	 * doing a redirect.
	 */
	private boolean includeLoginForm;

	/**
	 * The resource resolver factory used to resolve the login form as a resource
	 */
	@Reference(policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.OPTIONAL_UNARY)
	private ResourceResolverFactory resourceResolverFactory;

	/**
	 * If true the login form will be presented when the token expires.
	 */
	private boolean loginAfterExpire;


	@Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY, policy=ReferencePolicy.DYNAMIC)
	private SlingRepository repository;

	/**
	 * Extracts cookie/session based credentials from the request. Returns
	 * <code>null</code> if the handler assumes HTTP Basic authentication would
	 * be more appropriate, if no form fields are present in the request and if
	 * the secure user data is not present either in the cookie or an HTTP
	 * Session.
	 */
	@Override
	public AuthenticationInfo extractCredentials(HttpServletRequest request,
			HttpServletResponse response) {

		AuthenticationInfo info = null;

		// 1. try credentials from POST'ed request parameters
		info = this.extractRequestParameterAuthentication(request);

		// 2. try credentials from the cookie or session
		if (info == null) {
			String authData = authStorage.extractAuthenticationInfo(request);
			if (authData != null) {
				if (tokenStore.isValid(authData)) {
					info = createAuthInfo(authData);
				} else {
					// clear the cookie, its invalid and we should get rid of it
					// so that the invalid cookie isn't present on the authN
					// operation.
					authStorage.clear(request, response);
					if (this.loginAfterExpire || AuthUtil.isValidateRequest(request)) {
						// signal the requestCredentials method a previous login
						// failure
						request.setAttribute(AuthenticationHandler.FAILURE_REASON, FormReason.TIMEOUT);
						info = AuthenticationInfo.FAIL_AUTH;
					}
				}
			}
		}

		return info;
	}

	private String getUserIdByProperty(final UserManager userManager,
			final String propName, final String propValue) {
		String userId = null;
		try {
			Iterator<?> users = userManager.findAuthorizables(propName,
					propValue, UserManager.SEARCH_TYPE_USER);

			// use the first user found
			if (users.hasNext()) {
				userId = ((User) users.next()).getID();

				// warn if more than one user found
				if (users.hasNext()) {
					log.warn(
							"getUserName: Multiple users found with property {}={}; using {}",
							new Object[] { propName, propValue, userId });
				}
			}
		} catch (RepositoryException re) {
			log.warn("getUserName: Problem finding user with property {}={}",
					new Object[] { propName, propValue }, re);
		}

		return userId;
	}


	/**
	 * Copy LDAP user properties to JCR User properties
	 * @param ldapUser
	 */
	private void updateUserAttributes(Session session, LdapUser ldapUser, Authorizable user) {
		// Collecting attribute names
		try {
			for (Iterator e = user.getPropertyNames(); e.hasNext();) {
				user.removeProperty((String)e.next());
			}
			
			for (NamingEnumeration<? extends Attribute> ae = ldapUser.getAttributes().getAll(); ae.hasMore();) {
				Attribute attr = ae.next();
				log.info("Attribute: " + attr.getID());
				// multi value attribute
				if (attr.size() > 1) {
					Value[] props = new Value[attr.size()];
					int i = 0;
					for (NamingEnumeration e = attr.getAll(); e.hasMore();) {
						Object o = e.next();
						if (o instanceof String)
							props[i] = session.getValueFactory().createValue((String)o);
						i++;
					}
					user.setProperty(attr.getID(), props);
				} else {
					if (attr.get(0) instanceof String)
						user.setProperty(attr.getID(), session.getValueFactory().createValue((String)attr.get(0)));
				}
			}
		} catch (Exception e) {
			log.error("Could not update user attributes", e);
		}

	}
	
	/**
	 * Find a JCR Repository user name for the given LdapUser. Uses the name
	 * from the user identifier. if not found and autoCreate is true, creating
	 * identifier and JCR user
	 */
	private String getJcrUserNameByLdapUser(final LdapUser ldapUser) {

		// First check the object contains JCR name or not. If it os contains it's not neccessary to
		// authenticate via Ldap, already authenticated
		final Object nickname = ldapUser.getJcrUserName();
		if (nickname instanceof String) {
			return (String) nickname;
		}

		// Second we are searching for user who have the ldap identity property in JCR user.
		// If it is found we use that credential for authorization in JCR. So it is possible to map
		// several Ldap user for one JCR user.
		final String identity = ldapUser.getUserName();
		String userId = null;
		Session session = null;
		UserManager userManager = null;
		try {
			session = repository.loginAdministrative(null);
			userManager = AccessControlUtil.getUserManager(session);
			if (userManager != null) {
				userId = getUserIdByProperty(userManager, identityProperty,
						identity);
			}
		} catch (RepositoryException e) {
			log.error("Could not get repository user manager");
		}		

		// still null, use some dummy value to fail login and be able
		// to associate user afterwards		
		if (userId == null) {
			userId = "::not_valid_for_login::";

			if (autoCreateJcrUser) {
				// Authenticate in LDAP. If the login is correct, creating user in JCR repository.
				SimpleCredentials creds = new SimpleCredentials(identity, ldapUser.getPassword().toCharArray());
				creds.setAttribute(attrLdapId, ldapUser);
				boolean ldapValid = false;
				try {
					ldapValid = isLdapValid(creds);
				} catch (RepositoryException e1) {
				}
				
				if (!ldapValid) {
					if (session != null && session.isLive()) {
						session.logout();
					}
					return userId;
				}
				Authorizable user = null;
				
				// Auto create create user in Jcr repository or setting the identity property
				try {
					try {
						user = userManager.getAuthorizable(identity);
					} catch (Exception e) {
					}
					// User already exists, updating properties from LDAP
					if (user != null && !user.isGroup()) {
						user.setProperty(identityProperty, session.getValueFactory().createValue(identity));
						userId = identity;
						updateUserAttributes(session, ldapUser, user);
					} else if (user == null) {
						if (userManager != null) {
							log.info("Creating user: "+identity+" in JCR Repository");
							user = userManager.createUser(ldapUser.getUserName(), ldapUser.getPassword());
							user.setProperty(identityProperty, session.getValueFactory().createValue(identity));
							userId = identity;
							updateUserAttributes(session, ldapUser, user);
						}
					} else {
						log.error("The given principal is already exists as Group");
					}
				} catch (Exception e) {
					log.error("Could not fetch user: "+identity);
				}
			}
		}

		if (session != null && session.isLive()) {
			try {
				if (session.hasPendingChanges())
					session.save();
			} catch (Exception e) {
				log.error("Could not save "+identity+" in repository");
			}
			session.logout();
		}
		return userId;
	}

	/**
	 * Unless the <code>sling:authRequestLogin</code> to anything other than
	 * <code>Form</code> this method either sends back a 403/FORBIDDEN response
	 * if the <code>j_verify</code> parameter is set to <code>true</code> or
	 * redirects to the login form to ask for credentials.
	 * <p>
	 * This method assumes the <code>j_verify</code> request parameter to only
	 * be set in the initial username/password submission through the login
	 * form. No further checks are applied, though, before sending back the
	 * 403/FORBIDDEN response.
	 */
	@Override
	public boolean requestCredentials(HttpServletRequest request,
			HttpServletResponse response) throws IOException {

		// 0. ignore this handler if an authentication handler is requested
		if (ignoreRequestCredentials(request)) {
			// consider this handler is not used
			return false;
		}

		final String resource = AuthUtil.setLoginResourceAttribute(request,
				request.getRequestURI());

		if (includeLoginForm && (resourceResolverFactory != null)) {
			ResourceResolver resourceResolver = null;
			try {
				resourceResolver = resourceResolverFactory.getAdministrativeResourceResolver(null);
				Resource loginFormResource = resourceResolver.resolve(loginForm);
				Servlet loginFormServlet = loginFormResource.adaptTo(Servlet.class);
				if (loginFormServlet != null) {
					try {
						loginFormServlet.service(request, response);
						return true;
					} catch (ServletException e) {
						log.error("Failed to include the form: " + loginForm, e);
					}
				}
			} catch (LoginException e) {
				log.error("Unable to get a resource resolver to include for the login resource. Will redirect instead.");
			} finally {
				if (resourceResolver != null) {
					resourceResolver.close();
				}
			}
		}

		HashMap<String, String> params = new HashMap<String, String>();
		params.put(Authenticator.LOGIN_RESOURCE, resource);

		// append indication of previous login failure
		if (request.getAttribute(AuthenticationHandler.FAILURE_REASON) != null) {
			final Object jReason = request.getAttribute(AuthenticationHandler.FAILURE_REASON);
			@SuppressWarnings("rawtypes")
			final String reason = (jReason instanceof Enum)
			? ((Enum) jReason).name()
					: jReason.toString();
			params.put(AuthenticationHandler.FAILURE_REASON, reason);
		}

		try {
			AuthUtil.sendRedirect(request, response, loginForm, params);
		} catch (IOException e) {
			log.error("Failed to redirect to the login form " + loginForm, e);
		}

		return true;
	}

	/**
	 * Clears all authentication state which might have been prepared by this
	 * authentication handler.
	 */
	@Override
	public void dropCredentials(HttpServletRequest request,
			HttpServletResponse response) {
		authStorage.clear(request, response);
	}

	// ---------- AuthenticationFeedbackHandler

	/**
	 * Called after an unsuccessful login attempt. This implementation makes
	 * sure the authentication data is removed either by removing the cookie or
	 * by remove the HTTP Session attribute.
	 */
	@Override
	public void authenticationFailed(HttpServletRequest request,
			HttpServletResponse response, AuthenticationInfo authInfo) {

		/*
		 * Note: This method is called if this handler provided credentials
		 * which cause a login failure
		 */

		// clear authentication data from Cookie or Http Session
		authStorage.clear(request, response);

		// signal the reason for login failure
		request.setAttribute(AuthenticationHandler.FAILURE_REASON, FormReason.INVALID_CREDENTIALS);
	}

	/**
	 * Called after successfull login with the given authentication info. This
	 * implementation ensures the authentication data is set in either the
	 * cookie or the HTTP session with the correct security tokens.
	 * <p>
	 * If no authentication data already exists, it is created. Otherwise if the
	 * data has expired the data is updated with a new security token and a new
	 * expiry time.
	 * <p>
	 * If creating or updating the authentication data fails, it is actually
	 * removed from the cookie or the HTTP session and future requests will not
	 * be authenticated any longer.
	 */
	@Override
	public boolean authenticationSucceeded(HttpServletRequest request,
			HttpServletResponse response, AuthenticationInfo authInfo) {

		/*
		 * Note: This method is called if this handler provided credentials
		 * which succeeded loging into the repository
		 */

		// ensure fresh authentication data
		refreshAuthData(request, response, authInfo);

		final boolean result;
		if (DefaultAuthenticationFeedbackHandler.handleRedirect(
				request, response)) {

			// terminate request, all done in the default handler
			result = false;

		} else {

			// check whether redirect is requested by the resource parameter

			final String resource = AuthUtil.getLoginResource(request, null);
			if (resource != null) {
				try {
					response.sendRedirect(resource);
				} catch (IOException ioe) {
					log.error("Failed to send redirect to: " + resource, ioe);
				}

				// terminate request, all done
				result = true;
			} else {
				// no redirect, hence continue processing
				result = false;
			}

		}

		// no redirect
		return result;
	}

	@Override
	public String toString() {
		return "Ldap Based Authentication Handler";
	}

	// --------- Force HTTP Basic Auth ---------

	/**
	 * Returns <code>true</code> if this authentication handler should ignore
	 * the call to
	 * {@link #requestCredentials(HttpServletRequest, HttpServletResponse)}.
	 * <p>
	 * This method returns <code>true</code> if the
	 * {@link #REQUEST_LOGIN_PARAMETER} is set to any value other than "Form"
	 * (HttpServletRequest.FORM_AUTH).
	 */
	private boolean ignoreRequestCredentials(final HttpServletRequest request) {
		final String requestLogin = request.getParameter(AuthenticationHandler.REQUEST_LOGIN_PARAMETER);
		return requestLogin != null
				&& !LDAP_AUTH.equals(requestLogin);
	}

	/**
	 * Ensures the authentication data is set (if not set yet) and the expiry
	 * time is prolonged (if auth data already existed).
	 * <p>
	 * This method is intended to be called in case authentication succeeded.
	 *
	 * @param request The curent request
	 * @param response The current response
	 * @param authInfo The authentication info used to successfull log in
	 */
	private void refreshAuthData(final HttpServletRequest request,
			final HttpServletResponse response,
			final AuthenticationInfo authInfo) {

		// get current authentication data, may be missing after first login
		String authData = getCookieAuthData(authInfo);

		// check whether we have to "store" or create the data
		final boolean refreshCookie = needsRefresh(authData,
				this.sessionTimeout);

		// add or refresh the stored auth hash
		if (refreshCookie) {
			long expires = System.currentTimeMillis() + this.sessionTimeout;
			try {
				authData = null;
				authData = tokenStore.encode(expires, authInfo.getUser());
			} catch (InvalidKeyException e) {
				log.error(e.getMessage(), e);
			} catch (IllegalStateException e) {
				log.error(e.getMessage(), e);
			} catch (UnsupportedEncodingException e) {
				log.error(e.getMessage(), e);
			} catch (NoSuchAlgorithmException e) {
				log.error(e.getMessage(), e);
			}

			if (authData != null) {
				authStorage.set(request, response, authData, authInfo);
			} else {
				authStorage.clear(request, response);
			}
		}
	}

	// --------- Request Parameter Auth ---------

	private AuthenticationInfo extractRequestParameterAuthentication(
			HttpServletRequest request) {
		AuthenticationInfo info = null;

		// only consider login form parameters if this is a POST request
		// to the j_security_check URL
		if (REQUEST_METHOD.equals(request.getMethod())
				&& request.getRequestURI().endsWith(REQUEST_URL_SUFFIX)) {

			String user = request.getParameter(PAR_J_USERNAME);
			String pwd = request.getParameter(PAR_J_PASSWORD);

			if (user != null && pwd != null) {
				//info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH,
				//    user, pwd.toCharArray());

				// Get Ldap username from user
				LdapUser ldapUser = new LdapUser();
				ldapUser.setUserName(user);
				ldapUser.setPassword(pwd);
				String userId = getJcrUserNameByLdapUser(ldapUser);
				ldapUser.setJcrUserName(userId);
				info = getAuthInfoFromLdapUser(ldapUser);

				// if this request is providing form credentials, we have to
				// make sure, that the request is redirected after successful
				// authentication, otherwise the request may be processed
				// as a POST request to the j_security_check page (unless
				// the j_validate parameter is set); but only if this is not
				// a validation request

				if (!AuthUtil.isValidateRequest(request)) {
					AuthUtil.setLoginResourceAttribute(request, request.getContextPath());
				}
			}
		}

		return info;
	}

	private AuthenticationInfo createAuthInfo(final String authData) {
		final String userId = getUserId(authData);
		if (userId == null) {
			return null;
		}

		final AuthenticationInfo info = new AuthenticationInfo(
				LDAP_AUTH, userId);
		info.put(attrCookieAuthData, authData);

		return info;
	}

	private String getCookieAuthData(final AuthenticationInfo info) {
		Object data = info.get(attrCookieAuthData);
		if (data instanceof String) {
			return (String) data;
		}
		return null;
	}

	// ---------- LoginModulePlugin support

	private String getCookieAuthData(final Credentials credentials) {
		if (credentials instanceof SimpleCredentials) {
			Object data = ((SimpleCredentials) credentials).getAttribute(attrCookieAuthData);
			if (data instanceof String) {
				return (String) data;
			}
		}

		// no SimpleCredentials or no valid attribute
		return null;
	}

	private LdapUser getLdapAuthData(final Credentials credentials) {
		if (credentials instanceof SimpleCredentials) {
			Object data = ((SimpleCredentials) credentials).getAttribute(attrLdapId);
			if (data instanceof LdapUser) {
				return (LdapUser) data;
			}
		}

		// no SimpleCredentials or no valid attribute
		return null;
	}


	boolean hasAuthData(final Credentials credentials) {
		LdapUser ldapUser = getLdapAuthData(credentials);
		String authData = getCookieAuthData(credentials);
		boolean ret = false;
		if (authData != null) {
			ret = tokenStore.isValid(authData);
		} else if (ldapUser != null) {
			ret = true;
		}	
		return ret;
	}

	boolean isCookieValid(final Credentials credentials) {
		String authData = getCookieAuthData(credentials);
		if (authData != null) {
			return tokenStore.isValid(authData);
		}
		// no authdata, not valid
		return false;
	}

	boolean isLdapValid(final Credentials credentials) throws RepositoryException {
		LdapUser ldapUser = getLdapAuthData(credentials);
		if (ldapUser != null) {
			Hashtable<String, String> authEnv = new Hashtable<String, String>(11);
			//String dn = "uid=" + ldapUser.getUserName() + "," + ldapBase;
			String dn = StringUtils.replace(ldapBase, "${userName}", ldapUser.getUserName());
			authEnv.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
			authEnv.put(Context.PROVIDER_URL, ldapUrl);
			authEnv.put(Context.SECURITY_AUTHENTICATION, ldapAuthenticationType);
			authEnv.put(Context.SECURITY_PRINCIPAL, dn);
			authEnv.put(Context.SECURITY_CREDENTIALS, ldapUser.getPassword());
			try {
				DirContext ctx = new InitialDirContext(authEnv);
				Attributes attributes = ctx.getAttributes(dn);
				ldapUser.setAttributes(attributes);
				return true;
			} catch (AuthenticationException authEx) {
				return false;

			} catch (NamingException namEx) {
				throw new RepositoryException("Ldap Error:"+namEx.getExplanation());
			}
		}
		// no authdata, not valid
		return false;
	}

	private AuthenticationInfo getAuthInfoFromLdapUser(final LdapUser user) {
		final AuthenticationInfo info = new AuthenticationInfo(
				LDAP_AUTH, getJcrUserNameByLdapUser(user));

		// if there is no login module plugin service, set the credentials
		// attribute to the user's JCR identity, otherwise set it to
		// the actual LDAP User object
		if (loginModule == null) {
			info.put(attrLdapId, user.getJcrUserName());
		} else {
			info.put(attrLdapId, user);
		}

		return info;
	}

	// ---------- SCR Integration ----------------------------------------------

	/**
	 * Called by SCR to activate the authentication handler.
	 *
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalStateException
	 * @throws UnsupportedEncodingException
	 */
	@Activate
	protected void activate(ComponentContext componentContext)
			throws InvalidKeyException, NoSuchAlgorithmException,
			IllegalStateException, UnsupportedEncodingException {

		Dictionary<?, ?> properties = componentContext.getProperties();

		this.loginForm = PropertiesUtil.toString(properties.get(PAR_LOGIN_FORM),
				AuthenticationFormServlet.SERVLET_PATH);
		log.info("Login Form URL {}", loginForm);

		final String authName = PropertiesUtil.toString(
				properties.get(PAR_AUTH_NAME), DEFAULT_AUTH_NAME);

		String defaultCookieDomain = PropertiesUtil.toString(
				properties.get(PAR_DEFAULT_COOKIE_DOMAIN), "");
		if (defaultCookieDomain.length() == 0) {
			defaultCookieDomain = null;
		}

		authStorageType = PropertiesUtil.toString(
				properties.get(PAR_AUTH_STORAGE), DEFAULT_AUTH_STORAGE);
		if (AUTH_STORAGE_SESSION_ATTRIBUTE.equals(authStorageType)) {

			this.authStorage = new SessionStorage(authName);
			log.info("Using HTTP Session store with attribute name {}",
					authName);

		} else {

			this.authStorage = new CookieStorage(authName, defaultCookieDomain);
			log.info("Using Cookie store with name {}", authName);

		}

		this.attrCookieAuthData = PropertiesUtil.toString(
				properties.get(PAR_CREDENTIALS_ATTRIBUTE_NAME),
				DEFAULT_CREDENTIALS_ATTRIBUTE_NAME);
		log.info("Setting Auth Data attribute name {}", attrCookieAuthData);

		int timeoutMinutes = PropertiesUtil.toInteger(
				properties.get(PAR_AUTH_TIMEOUT), DEFAULT_AUTH_TIMEOUT);
		if (timeoutMinutes < 1) {
			timeoutMinutes = DEFAULT_AUTH_TIMEOUT;
		}
		log.info("Setting session timeout {} minutes", timeoutMinutes);
		this.sessionTimeout = MINUTES * timeoutMinutes;

		final String tokenFileName = PropertiesUtil.toString(
				properties.get(PAR_TOKEN_FILE), DEFAULT_TOKEN_FILE);
		final File tokenFile = getTokenFile(tokenFileName,
				componentContext.getBundleContext());
		final boolean fastSeed = PropertiesUtil.toBoolean(
				properties.get(PAR_TOKEN_FAST_SEED), DEFAULT_TOKEN_FAST_SEED);
		log.info("Storing tokens in {}", tokenFile.getAbsolutePath());
		this.tokenStore = new TokenStore(tokenFile, sessionTimeout, fastSeed);

		this.loginModule = null;
		try {
			this.loginModule = LdapLoginModulePlugin.register(this,
					componentContext.getBundleContext());
		} catch (Throwable t) {
			log.info("Cannot register LdapLoginModulePlugin. This is expected if Sling LdapModulePlugin services are not supported");
			log.debug("dump", t);
		}

		this.includeLoginForm = PropertiesUtil.toBoolean(properties.get(PAR_INCLUDE_FORM), DEFAULT_INCLUDE_FORM);

		this.loginAfterExpire = PropertiesUtil.toBoolean(properties.get(PAR_LOGIN_AFTER_EXPIRE), DEFAULT_LOGIN_AFTER_EXPIRE);

		this.identityProperty = PropertiesUtil.toString(
				properties.get(PAR_LDAP_ID_IDENTIFIER_PROPERTY),
				DEFAULT_LDAP_ID_IDENTIFIER_PROPERTY);
		log.info("Setting Identity attribute name {}", identityProperty);

		this.attrLdapId = PropertiesUtil.toString(
				properties.get(PAR_LDAP_USER_ATTR),
				DEFAULT_LDAP_USER_ATTR);
		log.info("Setting Ldap Id attribute name {}", attrLdapId);

		this.ldapUrl = PropertiesUtil.toString(
				properties.get(PAR_LDAP_URL),
				DEFAULT_LDAP_URL);
		log.info("Setting Ldap Url name {}", ldapUrl);

		this.ldapBase = PropertiesUtil.toString(
				properties.get(PAR_LDAP_BASE),
				DEFAULT_LDAP_BASE);
		log.info("Setting Ldap Base name {}", ldapBase);

		this.ldapAuthenticationType = PropertiesUtil.toString(
				properties.get(PAR_LDAP_AUTHENTICATION_TYPE),
				DEFAULT_LDAP_AUTHENTICATION_TYPE);
		log.info("Setting Ldap Authentication Type {}", ldapAuthenticationType);

		this.autoCreateJcrUser = PropertiesUtil.toBoolean(properties.get(PAR_AUTOCREATE_JCR_USER), DEFAULT_AUTOCREATE_JCR_USER);
		log.info("Setting AutoCreate JCR user {}", autoCreateJcrUser);

		this.userAttributes = PropertiesUtil.toStringArray(properties.get(PAR_USER_ATTRIBUTES), DEFAULT_USER_ATTRIBUTES);
		log.info("Setting User Attributes {}", userAttributes);


	}

	protected void deactivate(
			ComponentContext componentContext) {
		if (loginModule != null) {
			loginModule.unregister();
			loginModule = null;
		}
	}

	/**
	 * Returns an absolute file indicating the file to use to persist the
	 * security tokens.
	 * <p>
	 * This method is not part of the API of this class and is package private
	 * to enable unit tests.
	 *
	 * @param tokenFileName The configured file name, must not be null
	 * @param bundleContext The BundleContext to use to make an relative file
	 *            absolute
	 * @return The absolute file
	 */
	File getTokenFile(final String tokenFileName,
			final BundleContext bundleContext) {
		File tokenFile = new File(tokenFileName);
		if (tokenFile.isAbsolute()) {
			return tokenFile;
		}

		tokenFile = bundleContext.getDataFile(tokenFileName);
		if (tokenFile == null) {
			final String slingHome = bundleContext.getProperty("sling.home");
			if (slingHome != null) {
				tokenFile = new File(slingHome, tokenFileName);
			} else {
				tokenFile = new File(tokenFileName);
			}
		}

		return tokenFile.getAbsoluteFile();
	}

	/**
	 * Returns the user id from the authentication data. If the authentication
	 * data is a non-<code>null</code> value with 3 fields separated by an @
	 * sign, the value of the third field is returned. Otherwise
	 * <code>null</code> is returned.
	 * <p>
	 * This method is not part of the API of this class and is package private
	 * to enable unit tests.
	 *
	 * @param authData
	 * @return
	 */
	String getUserId(final String authData) {
		if (authData != null) {
			String[] parts = TokenStore.split(authData);
			if (parts != null) {
				return parts[2];
			}
		}
		return null;
	}

	/**
	 * Refresh the cookie periodically.
	 *
	 * @param sessionTimeout time to live for the session
	 * @return true or false
	 */
	private boolean needsRefresh(final String authData,
			final long sessionTimeout) {
		boolean updateCookie = false;
		if (authData == null) {
			updateCookie = true;
		} else {
			String[] parts = TokenStore.split(authData);
			if (parts != null && parts.length == 3) {
				long cookieTime = Long.parseLong(parts[1].substring(1));
				if (System.currentTimeMillis() + (sessionTimeout / 2) > cookieTime) {
					updateCookie = true;
				}
			}
		}
		return updateCookie;
	}

	/**
	 * The <code>AuthenticationStorage</code> interface abstracts the API
	 * required to store the {@link CookieAuthData} in an HTTP cookie or in an
	 * HTTP Session. The concrete class -- {@link CookieExtractor} or
	 * {@link SessionExtractor} -- is selected using the
	 * {@link CookieAuthenticationHandler#PAR_AUTH_HASH_STORAGE} configuration
	 * parameter, {@link CookieExtractor} by default.
	 */
	private static interface AuthenticationStorage {
		String extractAuthenticationInfo(HttpServletRequest request);

		void set(HttpServletRequest request, HttpServletResponse response,
				String authData, AuthenticationInfo info);

		void clear(HttpServletRequest request, HttpServletResponse response);
	}

	/**
	 * The <code>CookieExtractor</code> class supports storing the
	 * {@link CookieAuthData} in an HTTP Cookie.
	 */
	private static class CookieStorage implements AuthenticationStorage {

		/**
		 * The Set-Cookie header used to manage the login cookie.
		 *
		 * @see CookieStorage#setCookie(HttpServletRequest, HttpServletResponse,
		 *      String, String, int, String)
		 */
		private static final String HEADER_SET_COOKIE = "Set-Cookie";

		private final String cookieName;
		private final String domainCookieName;
		private final String defaultCookieDomain;

		public CookieStorage(final String cookieName, final String defaultCookieDomain) {
			this.cookieName = cookieName;
			this.domainCookieName = cookieName + "." + COOKIE_DOMAIN;
			this.defaultCookieDomain = defaultCookieDomain;
		}

		@Override
		public String extractAuthenticationInfo(HttpServletRequest request) {
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					if (this.cookieName.equals(cookie.getName())) {
						// found the cookie, so try to extract the credentials
						// from it and reverse the base64 encoding
						String value = cookie.getValue();
						if (value.length() > 0) {
							try {
								return new String(Base64.decodeBase64(value),
										"UTF-8");
							} catch (UnsupportedEncodingException e1) {
								throw new RuntimeException(e1);
							}
						}
					}
				}
			}

			return null;
		}

		@Override
		public void set(HttpServletRequest request,
				HttpServletResponse response, String authData, AuthenticationInfo info) {
			// base64 encode to handle any special characters
			String cookieValue;
			try {
				cookieValue = Base64.encodeBase64URLSafeString(authData.getBytes("UTF-8"));
			} catch (UnsupportedEncodingException e1) {
				throw new RuntimeException(e1);
			}

			// send the cookie to the response
			String cookieDomain = (String) info.get(COOKIE_DOMAIN);
			if (cookieDomain == null || cookieDomain.length() == 0) {
				cookieDomain = defaultCookieDomain;
			}
			setCookie(request, response, this.cookieName, cookieValue, -1,
					cookieDomain);

			// send the cookie domain cookie if domain is not null
			if (cookieDomain != null) {
				setCookie(request, response, this.domainCookieName,
						cookieDomain, -1, cookieDomain);
			}
		}

		@Override
		public void clear(HttpServletRequest request,
				HttpServletResponse response) {
			Cookie oldCookie = null;
			String oldCookieDomain = null;
			Cookie[] cookies = request.getCookies();
			if (cookies != null) {
				for (Cookie cookie : cookies) {
					if (this.cookieName.equals(cookie.getName())) {
						// found the cookie
						oldCookie = cookie;
					} else if (this.domainCookieName.equals(cookie.getName())) {
						oldCookieDomain = cookie.getValue();
					}
				}
			}

			// remove the old cookie from the client
			if (oldCookie != null) {
				setCookie(request, response, this.cookieName, "", 0, oldCookieDomain);
				if (oldCookieDomain != null && oldCookieDomain.length() > 0) {
					setCookie(request, response, this.domainCookieName, "", 0, oldCookieDomain);
				}
			}
		}

		private void setCookie(final HttpServletRequest request,
				final HttpServletResponse response, final String name,
				final String value, final int age, final String domain) {

			final String ctxPath = request.getContextPath();
			final String cookiePath = (ctxPath == null || ctxPath.length() == 0)
					? "/"
							: ctxPath;

			/*
			 * The Servlet Spec 2.5 does not allow us to set the commonly used
			 * HttpOnly attribute on cookies (Servlet API 3.0 does) so we create
			 * the Set-Cookie header manually. See
			 * http://www.owasp.org/index.php/HttpOnly for information on what
			 * the HttpOnly attribute is used for.
			 */

			final StringBuilder header = new StringBuilder();

			// default setup with name, value, cookie path and HttpOnly
			header.append(name).append("=").append(value);
			header.append("; Path=").append(cookiePath);
			header.append("; HttpOnly"); // don't allow JS access

			// set the cookie domain if so configured
			if (domain != null) {
				header.append("; Domain=").append(domain);
			}

			// Only set the Max-Age attribute to remove the cookie
			if (age >= 0) {
				header.append("; Max-Age=").append(age);
			}

			// ensure the cookie is secured if this is an https request
			if (request.isSecure()) {
				header.append("; Secure");
			}

			response.addHeader(HEADER_SET_COOKIE, header.toString());
		}
	}

	/**
	 * The <code>SessionExtractor</code> class provides support to store the
	 * {@link CookieAuthData} in an HTTP Session.
	 */
	private static class SessionStorage implements AuthenticationStorage {
		private final String sessionAttributeName;

		SessionStorage(final String sessionAttributeName) {
			this.sessionAttributeName = sessionAttributeName;
		}

		@Override
		public String extractAuthenticationInfo(HttpServletRequest request) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				Object attribute = session.getAttribute(sessionAttributeName);
				if (attribute instanceof String) {
					return (String) attribute;
				}
			}
			return null;
		}

		@Override
		public void set(HttpServletRequest request,
				HttpServletResponse response, String authData, AuthenticationInfo info) {
			// store the auth hash as a session attribute
			HttpSession session = request.getSession();
			session.setAttribute(sessionAttributeName, authData);
		}

		@Override
		public void clear(HttpServletRequest request,
				HttpServletResponse response) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				session.removeAttribute(sessionAttributeName);
			}
		}

	}
}