/**
 * Copyright 2016 Angus Warren
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

package anguswarren.confluence;

import org.apache.log4j.Logger;
import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.confluence.user.ConfluenceUser;
import com.atlassian.confluence.user.AuthenticatedUserThreadLocal;
import com.atlassian.spring.container.ContainerManager;
import com.atlassian.confluence.user.UserAccessor;

@SuppressWarnings("serial")
public class RemoteUserConfluenceAuth extends ConfluenceAuthenticator {
    private static final Logger log = Logger.getLogger(RemoteUserConfluenceAuth.class);

    private static final String workDirHint = "CATALINA_HOME"+File.separator;
    private static final String confPath = "conf"+File.separator;
    private static final String propsFile = "RemoteUserConfluenceAuth.properties";
    private static final Properties props = initProps();
    private static final Properties initProps() {
        Properties p = new Properties();

        try {
            p.load(new FileInputStream(new File(confPath+propsFile)));
            log.debug("Properties loaded from file: "+workDirHint+confPath+propsFile);
        } catch (java.io.FileNotFoundException e) {
            log.warn("Optional properties file not found at "+workDirHint+confPath+propsFile);
        } catch (Exception e) {
            log.error("Error loading properties file: "+workDirHint+confPath+propsFile + e, e);
        }

        // Default values...
        if (p.getProperty("defaultgroups") == null) p.setProperty("defaultgroups", "confluence-users");
        if (p.getProperty("format") == null) p.setProperty("format", "username");
        if (p.getProperty("header") == null) p.setProperty("header", "REMOTE_USER");
        if (p.getProperty("trustedhosts") == null) p.setProperty("trustedhosts", "");

        // Sanitise values...
        if (!p.getProperty("format").equals("email")) p.setProperty("format", "username");

        // Due diligence...
        p.setProperty("header",p.getProperty("header").toUpperCase());
        if (!p.getProperty("header").equals("REMOTE_USER") && p.getProperty("trustedhosts").equals("")) {
            p.setProperty("trustedhosts", "127.0.0.1");
            log.error(workDirHint+confPath+propsFile+" values would allow insecure HTTP header SSO without any 'trustedhosts'! "+
                    "Please ensure 'trustedhosts' is configured appropriately (currently defaulting to 127.0.0.1). "+
                    "If you must use this configuration in a non-production scenario, access the site locally or via an ssh tunnel.");
        }

        log.info("Runtime properties:");
        p.forEach((k,v) -> log.info(k+"="+v));

        return p;
    }

    private ConfluenceUser getAdminUser() {
        UserAccessor userAccessor = (UserAccessor) ContainerManager.getComponent("userAccessor");
        List<String> adminUsernames = userAccessor.getMemberNamesAsList(userAccessor.getGroup("confluence-administrators"));
        if ( adminUsernames != null && !adminUsernames.isEmpty() ) {
            for ( String username : adminUsernames ) {
                if ( !userAccessor.isDeactivated(username) ) return userAccessor.getUserByName(username);
            }
        }
        return null;
    }

    private ConfluenceUser activateUser( String username, String defaultGroups ) {
        UserAccessor userAccessor = (UserAccessor) ContainerManager.getComponent("userAccessor");
        if (!userAccessor.exists(username)) {
            log.warn( "Unable to activate unregistered user: " + username );
            return null;
        }
        log.debug("User account exists: " + username);

        // TODO: Test if user is activated AND in default groups before any privilege escalation,
        // this would make the method more robust if it can't find an admin account

        ConfluenceUser userManagementAccount = getAdminUser();
        if ( userManagementAccount != null ) {
            ConfluenceUser user = userAccessor.getUserByName(username);
            AuthenticatedUserThreadLocal.set(userManagementAccount);
            try {
                if (userAccessor.isDeactivated(username)) {
                    log.warn("Reactivating user: "+username);
                    userAccessor.reactivateUser(user);
                }
                for (String group: defaultGroups.split(",")) {
                    group = group.trim();
                    if (!userAccessor.hasMembership(group, username)) {
                        log.warn("Adding '"+group+"' group membership to user: " + username);
                        userAccessor.addMembership(group, username);
                    }
                }
            } finally {
                AuthenticatedUserThreadLocal.reset();
            }
            log.debug("Account confirmed active with default group membership: " + username);
            return user;
        } else {
            log.error("An enabled admin account is required to perform account management operations, no such account could not be found.");
        }
        return null;
    }

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        Principal user = null;
        try {
            if (request.getSession() != null && request.getSession().getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY) != null) {
                log.debug("Session found; user already logged in");
                user = (Principal) request.getSession().getAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY);
                String username = user.getName();
                user = getUser(username);
            } else {
                String trustedhosts = props.getProperty("trustedhosts");
                String ipAddress = request.getRemoteAddr();
                if (!Arrays.asList(trustedhosts.split(",")).contains(ipAddress)) {
                    log.debug("IP not found in trustedhosts: " + ipAddress);
                    return null;
                }

                String upstreamUser = null;
                String header = props.getProperty("header");
                if ( header.equals("REMOTE_USER") ) {
                    log.debug("Trying REMOTE_USER (AJP) for SSO");
                    upstreamUser = request.getRemoteUser();
                } else {
                    log.debug("Trying HTTP header '" + header + "' for SSO");
                    upstreamUser = request.getHeader(header);
                }

                if (upstreamUser != null) {
                    log.debug("Raw upstream user information: "+ upstreamUser);
                    if ( props.getProperty("format").equals("username") ) {
                        upstreamUser = upstreamUser.split("@")[0];
                    }
                    upstreamUser = upstreamUser.trim();
                    log.debug("Formatted upstream user information: "+ upstreamUser);

                    user = (Principal) activateUser(upstreamUser, props.getProperty("defaultgroups"));
                    if ( user != null ) {
                        log.debug("Logging in with username: " + upstreamUser);
                        request.getSession().setAttribute(ConfluenceAuthenticator.LOGGED_IN_KEY, user);
                        request.getSession().setAttribute(ConfluenceAuthenticator.LOGGED_OUT_KEY, null);
                    } else {
                        log.warn("Unable to authorise access attempt: "+ upstreamUser);
                    }
                } else {
                    log.debug("HTTP header or REMOTE_USER not set (no upstream user session)");
                    return null;
                }
            }
        } catch (Exception e) {
            log.error("Exception: " + e, e);
        }
        return user;
    }
}
