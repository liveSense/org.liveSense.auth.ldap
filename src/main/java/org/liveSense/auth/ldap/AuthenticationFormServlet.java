package org.liveSense.auth.ldap;

import javax.servlet.http.HttpServletRequest;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.auth.core.spi.AbstractAuthenticationFormServlet;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.liveSense.auth.FormReason;


@Component(metatype=false)
@Service(value=javax.servlet.Servlet.class)
@Properties(value={
	@Property(name="service.vendor",value="LiveSense.org"),
	@Property(name="service.description", value="Default Login Form for Ldap Authentication"),
	@Property(name="sling.servlet.methods", value={"GET", "POST"}),
	@Property(name="sling.servlet.paths", value=AuthenticationFormServlet.SERVLET_PATH)
})

/**
 * The <code>AuthenticationFormServlet</code> provides the default login form
 * used for OpenID Authentication.
 *
 */
@SuppressWarnings("serial")
public class AuthenticationFormServlet extends AbstractAuthenticationFormServlet {

    /**
     * The constant is used to provide the service registration path
     */
	public static final String SERVLET_PATH = "/system/sling/ldap/login";

    /**
     * This constant is used to provide the service registration property
     * indicating to pass requests to this servlet unauthenticated.
     */
    @SuppressWarnings("unused")
    @Property(name="sling.auth.requirements")
    private static final String AUTH_REQUIREMENT = "-" + SERVLET_PATH;

    /**
     * Returns an informational message according to the value provided in the
     * <code>j_reason</code> request parameter. Supported reasons are invalid
     * credentials and session timeout.
     *
     * @param request The request providing the parameter
     * @return The "translated" reason to render the login form or an empty
     *         string if there is no specific reason
     */
    @Override
	protected String getReason(final HttpServletRequest request) {
        // return the resource attribute if set to a non-empty string
        Object resObj = request.getAttribute(AuthenticationHandler.FAILURE_REASON);
        if (resObj instanceof FormReason) {
            return ((FormReason) resObj).toString();
        }

        final String reason = request.getParameter(AuthenticationHandler.FAILURE_REASON);
        if (reason != null) {
            try {
                return FormReason.valueOf(reason).toString();
            } catch (IllegalArgumentException iae) {
                // thrown if the reason is not an expected value, assume none
            }

            // no valid FormReason value, use raw value
            return reason;
        }

        return "";
    }

}
