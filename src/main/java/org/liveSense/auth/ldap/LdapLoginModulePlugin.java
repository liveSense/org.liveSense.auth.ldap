package org.liveSense.auth.ldap;

import java.security.Principal;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.jcr.Credentials;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.security.auth.callback.CallbackHandler;

import org.apache.sling.jcr.jackrabbit.server.security.AuthenticationPlugin;
import org.apache.sling.jcr.jackrabbit.server.security.LoginModulePlugin;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceRegistration;


/**
 * The <code>LdapLoginModulePlugin</code> is a simple Sling LoginModulePlugin
 * enabling authentication of Ldap identifiers as Jackrabbit Repository users
 */
class LdapLoginModulePlugin implements LoginModulePlugin {

    private final LdapAuthenticationHandler authHandler;

    /**
     * Creates an instance of this class and registers it as a
     * <code>LoginModulePlugin</code> service to handle login requests with
     * <code>SimpleCredentials</code> provided by the
     * {@link LdapAuthenticationHandler}.
     *
     * @param authHandler The {@link LdapAuthenticationHandler} providing
     *            support to validate the credentials
     * @param bundleContext The <code>BundleContext</code> to register the
     *            service
     * @return The <code>ServiceRegistration</code> of the registered service
     *         for the {@link LdapAuthenticationHandler} to unregister the
     *         service on shutdown.
     */
    static ServiceRegistration register(
            final LdapAuthenticationHandler authHandler,
            final BundleContext bundleContext) {
        LdapLoginModulePlugin plugin = new LdapLoginModulePlugin(
            authHandler);

        Hashtable<String, Object> properties = new Hashtable<String, Object>();
        properties.put(Constants.SERVICE_DESCRIPTION,
            "LoginModulePlugin Support for LDapAuthenticationHandler");
        properties.put(Constants.SERVICE_VENDOR,
            bundleContext.getBundle().getHeaders().get(Constants.BUNDLE_VENDOR));

        return bundleContext.registerService(LoginModulePlugin.class.getName(),
            plugin, properties);
    }

    private LdapLoginModulePlugin(
            final LdapAuthenticationHandler authHandler) {
        this.authHandler = authHandler;
    }

    /**
     * This implementation does nothing.
     */
    @Override
	public void doInit(final CallbackHandler callbackHandler,
            final Session session, @SuppressWarnings("rawtypes") final Map options) {
        return;
    }

    /**
     * Returns <code>true</code> indicating support if the credentials is a
     * <code>SimplerCredentials</code> object and has an authentication data
     * attribute.
     * <p>
     * This method does not validate the data just checks its presence.
     *
     * @see CookieAuthenticationHandler#hasAuthData(Credentials)
     */
    @Override
	public boolean canHandle(Credentials credentials) {
    	return authHandler.hasAuthData(credentials); 
    }

    /**
     * Returns an authentication plugin which validates the authentication data
     * contained as an attribute in the credentials object. The
     * <code>authenticate</code> method returns <code>true</code> only if
     * authentication data is contained in the credentials (expected because
     * this method should only be called if {@link #canHandle(Credentials)}
     * returns <code>true</code>) and the authentication data is valid.
     */
    @Override
	public AuthenticationPlugin getAuthentication(final Principal principal,
            final Credentials creds) {
        return new AuthenticationPlugin() {
            @Override
			public boolean authenticate(Credentials credentials)
                    throws RepositoryException {

            	boolean valid = authHandler.isCookieValid(credentials);
            	
            	// If cookie is not valid, retry with LDAP
            	if (!valid) 
            	    valid = authHandler.isLdapValid(credentials);
            	
            	return valid;
            }

        };
    }

    /**
     * Returns <code>null</code> to have the <code>DefaultLoginModule</code>
     * provide a principal based on an existing user defined in the repository.
     */
    @Override
	public Principal getPrincipal(final Credentials credentials) {
	return null;
    }

    /**
     * This implementation does nothing.
     */
    @Override
	public void addPrincipals(@SuppressWarnings("rawtypes") final Set principals) {
    }

    /**
     * Returns <code>LoginModulePlugin.IMPERSONATION_DEFAULT</code> to indicate
     * that this plugin does not itself handle impersonation requests.
     */
    @Override
	public int impersonate(final Principal principal,
            final Credentials credentials) {
        return LoginModulePlugin.IMPERSONATION_DEFAULT;
    }

}