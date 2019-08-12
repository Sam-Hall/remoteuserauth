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

package anguswarren.jira;

import org.apache.log4j.Logger;
import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;
import java.util.SortedSet;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.jira.security.JiraAuthenticationContext;
import com.atlassian.jira.security.groups.GroupManager;
import com.atlassian.jira.bc.user.ApplicationUserBuilderImpl;
import com.atlassian.jira.bc.user.UserService;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.jira.user.util.UserManager;
import com.atlassian.jira.user.util.UserUtil;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;


@SuppressWarnings("serial")
public class RemoteUserJiraAuth extends JiraSeraphAuthenticator {
    private static final Logger log = Logger.getLogger(RemoteUserJiraAuth.class);

    private static final String appDir = System.getProperty("catalina.home")+File.separator;
    private static final String appDirHint = "CATALINA_HOME"+File.separator;
    private static final String confPath = "conf"+File.separator;
    private static final String propsFile = "RemoteUserJiraAuth.properties";
    private static final Properties props = initProps();
    private static final String[] ignorePaths = props.getProperty("ignorepaths").split(",");
    
    private static final Properties initProps() {
        Properties p = new Properties();

        try {
            p.load(new FileInputStream(new File(appDir+confPath+propsFile)));
            log.debug("Properties loaded from file: "+appDirHint+confPath+propsFile);
        } catch (java.io.FileNotFoundException e) {
            log.warn("Optional properties file not found at "+appDirHint+confPath+propsFile);
        } catch (Exception e) {
            log.error("Error loading properties file: "+appDirHint+confPath+propsFile + e, e);
        }

        // Default values...
        if (p.getProperty("defaultgroups") == null) p.setProperty("defaultgroups", "confluence-users");
        if (p.getProperty("groupsheader") == null) p.setProperty("groupsheader", "");
        if (p.getProperty("groupmanagement") == null) p.setProperty("groupmanagement", "optional");
        if (p.getProperty("format") == null) p.setProperty("format", "username");
        if (p.getProperty("header") == null) p.setProperty("header", "REMOTE_USER");
        if (p.getProperty("trustedhosts") == null) p.setProperty("trustedhosts", "");
        if (p.getProperty("ignorepaths") == null) p.setProperty("ignorepaths", "/login.jsp");

        // Sanitise values...
        //TODO: more effort here? trims and cases, etc. this only runs once after all, validate IP addresses and log errors
        if (!p.getProperty("groupsheader").equals("")) p.setProperty("defaultgroups", "");
        if (!p.getProperty("format").equals("email")) p.setProperty("format", "username");

        // Due diligence...
        p.setProperty("header",p.getProperty("header").toUpperCase());
        if (!p.getProperty("header").equals("REMOTE_USER") && p.getProperty("trustedhosts").equals("")) {
            p.setProperty("trustedhosts", "127.0.0.1");
            log.error(appDirHint+confPath+propsFile+" values would allow insecure HTTP header SSO without any 'trustedhosts'! "+
                    "Please ensure 'trustedhosts' is configured appropriately (currently defaulting to 127.0.0.1). "+
                    "If you must use this configuration in a non-production scenario, access the site locally or via an ssh tunnel.");
        }

        log.info("Runtime properties:");
        p.forEach((k,v) -> log.info(k+"="+v));

        return p;
    }

    /**
     * Returns an active user account from the jira-administrators group.
     * @return
     */
    private ApplicationUser getAdminUser() {
        GroupManager groupManager = ComponentAccessor.getGroupManager();

        Collection <ApplicationUser> adminUsers = groupManager.getUsersInGroup("jira-administrators",false);
        if ( adminUsers != null && adminUsers.size() > 0 ) {
            return adminUsers.iterator().next();
        }
        return null;
    }

    /**
     * Validate the user, ensure they can login according to the current
     * "groupmanagement" settings when requiredGroups are specified.
     * The method will also attempt to activate the user if for whatever
     * reason they may have become deactivated.
     *
     * @param username Atlassian username, case sensitive (must be lower-case)
     * @param requiredGroups Comma separated list of required groups
     * @return The validated user, confirmed ready for login. Otherwise, null.
     */
    private Principal validateUser( String username, String requiredGroups ) {
        UserService userService = ComponentAccessor.getComponent( UserService.class );
        UserManager userManager = ComponentAccessor.getUserManager();
        ApplicationUser appUser = userManager.getUserByKeyEvenWhenUnknown( username );

        if ( !userManager.isUserExisting(appUser) ) {
            log.warn( "Unable to activate unregistered user: " + username );
            return null;
        }
        log.debug("User account exists: " + username);

        if ( !requiredGroups.equals("") ) {
            UserUtil userUtil = ComponentAccessor.getUserUtil();
            GroupManager groupManager = ComponentAccessor.getGroupManager();

            SortedSet<String> groups = userUtil.getGroupNamesForUser(username);
            for (String requiredGroup: requiredGroups.split(",")) {
                requiredGroup = requiredGroup.toLowerCase().trim();
                if (!groups.contains(requiredGroup)) {
                    log.debug("User missing '"+requiredGroup+"' group membership: " + username);
                    if (props.getProperty("groupmanagement").contentEquals("required")) {
                        log.warn("Unable to authorise access attempt as user is missing required '"+requiredGroup+"' group membership: "+ username);
                        return null;
                    } else if (props.getProperty("groupmanagement").contentEquals("autojoin")) {
                        if (!groupManager.groupExists(requiredGroup)) {
                            /* Could auto-create group if it makes sense to allow the upstream proxy to do so,
                             * perhaps add an option for this. If group management becomes more sophisticated
                             * we'd need an "autosync" option, that doesn't just "autojoin", but also removes
                             * membership of any current internal groups which are absent from the header.
                             */
                            log.error("Can not add user to non-existant group '"+requiredGroup+"': "+ username);
                            return null;
                        }
                        log.warn("Adding '"+requiredGroup+"' group membership to user: " + username);
                        try {
                            groupManager.addUserToGroup( appUser, groupManager.getGroup( requiredGroup ) );
                        } catch (Exception e) {
                            log.error("Failed to add '"+requiredGroup+"' group membership: "+ e, e);
                            return null;
                        }
                    }
                } else {
                    log.debug("User has '"+requiredGroup+"' group membership: " + username);
                }
            }
        }

        if (!appUser.isActive()) {
            log.debug("Atempting to reactivate inactive user account: " + username);
            ApplicationUser userManagementAccount = getAdminUser();
            if ( userManagementAccount != null ) {
                JiraAuthenticationContext jiraAuthenticationContext = ComponentAccessor.getJiraAuthenticationContext();
                try {
                    jiraAuthenticationContext.setLoggedInUser(userManagementAccount);
                    ApplicationUser updateUser = (new ApplicationUserBuilderImpl(appUser)).active(true).build();
                    UserService.UpdateUserValidationResult updateUserValidationResult = userService.validateUpdateUser(updateUser);
                    if (updateUserValidationResult.isValid()) {
                        userService.updateUser(updateUserValidationResult);
                        log.warn("Reactivativated user account: " + username);
                    } else {
                        log.error("User could not be enabled, please confirm user directory settings: " + username);
                        return null;
                    }
                } catch (Exception e) {
                    log.error("User could not be enabled, an error occurred ("+e+"): "+username);
                    return null;
                } finally {
                    jiraAuthenticationContext.clearLoggedInUser();
                }
            } else {
                log.error("An enabled admin account is required to perform account management operations, no such account could not be found.");
                return null;
            }
        }
        log.debug("Account confirmed active with required group membership: " + username);
        return (Principal) appUser;
    }

    /**
     * Returns required groups string based on the properties.
     *
     * @return
     */
    private String getRequiredGroups( HttpServletRequest request ) {
        String requiredGroups;
        if ( props.getProperty("groupmanagement").contentEquals("optional") ) {
            return "";
        }
        if ( props.getProperty("groupsheader").contentEquals("") ) {
            requiredGroups = props.getProperty("defaultgroups");
        } else {
            requiredGroups = request.getHeader(props.getProperty("groupsheader"));
        }
        if ( requiredGroups == null ) requiredGroups = "";
        log.debug("Required group list: " + requiredGroups);
        return requiredGroups;
    }
    
    private boolean ignorePath( HttpServletRequest request ) {
        String uri = request.getRequestURI();
        String qs = request.getQueryString();
        for (String ignore: ignorePaths) {
            if ( ignore.contains("?") ) {
                if (qs != null && ignore.equals(uri+"?"+qs)) return true;
            } else {
                if ( uri.equals( ignore ) ) return true;
            }
        }
        return false;
    }

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        Principal userPrincipal = null;
        try {
            if ( ignorePath(request) ) {
                log.debug("Ignoring path: " + request.getRequestURI() + "[?]" + request.getQueryString());
                return null;
            }
            if (request.getSession() != null && request.getSession().getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY) != null) {
                log.debug("Session found; user already logged in");
                userPrincipal = (Principal) request.getSession().getAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY);
                String username = userPrincipal.getName();
                userPrincipal = getUser(username);
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
                    upstreamUser = upstreamUser.toLowerCase().trim();
                    log.debug("Formatted upstream user information: "+ upstreamUser);

                    userPrincipal = validateUser( upstreamUser, getRequiredGroups(request) );
                    if ( userPrincipal != null ) {
                        log.debug("Logging in with username: " + upstreamUser);
                        request.getSession().setAttribute(JiraSeraphAuthenticator.LOGGED_IN_KEY, userPrincipal);
                        request.getSession().setAttribute(JiraSeraphAuthenticator.LOGGED_OUT_KEY, null);
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
        return userPrincipal;
    }
}
