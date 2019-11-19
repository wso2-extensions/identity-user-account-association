/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.user.account.association;

import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.common.AuthenticationException;
import org.wso2.carbon.core.services.authentication.AuthenticationUtil;
import org.wso2.carbon.core.services.authentication.stats.LoginAttempt;
import org.wso2.carbon.core.services.authentication.stats.LoginStatDatabase;
import org.wso2.carbon.core.services.util.CarbonAuthenticationUtil;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.account.association.dao.UserAccountAssociationDAO;
import org.wso2.carbon.identity.user.account.association.dto.UserAccountAssociationDTO;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationClientException;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationServerException;
import org.wso2.carbon.identity.user.account.association.internal.IdentityAccountAssociationServiceComponent;
import org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants;
import org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ALREADY_CONNECTED;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ATTEMPTED_CROSS_TENANT_ASSOCIATION;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_RETRIEVING_TENANT_ID_OF_USER;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_ACCESSING_REALM_SERVICE;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_AUTHENTICATING_USER;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_EXECUTING_AUTHENTICATORS;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_GETTING_TENANT_ID;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_LOADING_REALM_SERVICE;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_RETRIEVING_REMOTE_ADDRESS;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_UPDATING_SESSION;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.INVALID_ASSOCIATION;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.INVALID_INPUTS;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.INVALID_TENANT_DOMAIN;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.SAME_ACCOUNT_CONNECTING_ERROR;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.USER_NOT_AUTHENTIC;
import static org.wso2.carbon.user.core.UserCoreConstants.TENANT_DOMAIN_COMBINER;

public class UserAccountConnectorImpl implements UserAccountConnector {

    private static final Log log = LogFactory.getLog(UserAccountConnectorImpl.class);
    private static final Log audit = CarbonConstants.AUDIT_LOG;

    private UserAccountConnectorImpl() {

    }

    private static class LazyHolder {
        private static final UserAccountConnectorImpl INSTANCE = new UserAccountConnectorImpl();
    }

    public static UserAccountConnectorImpl getInstance() {
        return LazyHolder.INSTANCE;
    }

    /**
     * Create new user account association
     *
     * @param userName1 Username of account 1
     * @param userName2 Username of account 2
     * @throws org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException
     */
    @Override
    public void createUserAccountAssociation(String userName1, String userName2) throws
            UserAccountAssociationException {

        if (StringUtils.isNotBlank(userName1) && StringUtils.isNotBlank(userName2)) {
            RealmService realmService;
            String tenantAwareUsername1 = MultitenantUtils.getTenantAwareUsername(userName1);
            String tenantAwareUsername2 = MultitenantUtils.getTenantAwareUsername(userName2);

            String user1Domain = IdentityUtil.extractDomainFromName(tenantAwareUsername1);
            String user2Domain = IdentityUtil.extractDomainFromName(tenantAwareUsername2);
            String username1WithoutDomain = UserAccountAssociationUtil.getUsernameWithoutDomain(tenantAwareUsername1);
            String username2WithoutDomain = UserAccountAssociationUtil.getUsernameWithoutDomain(tenantAwareUsername2);
            int user1Tenant;
            int user2Tenant;
            try {
                realmService = IdentityAccountAssociationServiceComponent.getRealmService();
                user1Tenant = realmService.getTenantManager().getTenantId(MultitenantUtils.getTenantDomain(userName1));
                user2Tenant = realmService.getTenantManager().getTenantId(MultitenantUtils.getTenantDomain(userName2));
                boolean user1Exists = realmService.getTenantUserRealm(user1Tenant).getUserStoreManager().isExistingUser(tenantAwareUsername1);
                boolean user2Exists = realmService.getTenantUserRealm(user2Tenant).getUserStoreManager()
                        .isExistingUser(tenantAwareUsername2);
                if (!user1Exists || !user2Exists) {
                    logWarnMessage(userName1, userName2, user1Exists, user2Exists);
                    return;
                }

            } catch (UserStoreException e) {
                throw handleUserAccountAssociationClientException(ERROR_RETRIEVING_TENANT_ID_OF_USER, null, true);
            }
            if (MultitenantConstants.INVALID_TENANT_ID == user1Tenant) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format(UserAccountAssociationConstants.ErrorMessages.DEBUG_INVALID_TENANT_DOMAIN
                            .getDescription(), MultitenantUtils.getTenantDomain(userName1)));
                }
                throw handleUserAccountAssociationClientException(INVALID_TENANT_DOMAIN, null, true);
            }
            if (MultitenantConstants.INVALID_TENANT_ID == user2Tenant) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format(UserAccountAssociationConstants.ErrorMessages.DEBUG_INVALID_TENANT_DOMAIN
                            .getDescription(), MultitenantUtils.getTenantDomain(userName2)));
                }
                throw handleUserAccountAssociationClientException(INVALID_TENANT_DOMAIN, null, true);
            }
            if (username1WithoutDomain.equals(username2WithoutDomain) && user1Domain.equals(user2Domain) &&
                    user1Tenant == user2Tenant) {
                if (log.isDebugEnabled()) {
                    log.debug(SAME_ACCOUNT_CONNECTING_ERROR.getDescription());

                }
                throw handleUserAccountAssociationClientException(SAME_ACCOUNT_CONNECTING_ERROR, null, true);
            }
            if (UserAccountAssociationDAO.getInstance().isValidUserAssociation(user1Domain, user1Tenant,
                    username1WithoutDomain, user2Domain, user2Tenant, username2WithoutDomain)) {
                if (log.isDebugEnabled()) {
                    log.debug(ALREADY_CONNECTED.getDescription());
                }
                throw handleUserAccountAssociationClientException(ALREADY_CONNECTED, null, true);
            }
            String associationKey = UserAccountAssociationDAO.getInstance().getAssociationKeyOfUser(user1Domain,
                    user1Tenant, username1WithoutDomain);
            boolean validAssociationKey = associationKey != null;

            // If connecting account already connected to other accounts
            String connUserAssociationKey = UserAccountAssociationDAO.getInstance().getAssociationKeyOfUser
                    (user2Domain, user2Tenant, username2WithoutDomain);

            boolean validConnUserAssociationKey = connUserAssociationKey != null;

            if (!validAssociationKey && !validConnUserAssociationKey) {
                String newAssociationKey = UserAccountAssociationUtil.getRandomNumber();
                UserAccountAssociationDAO.getInstance().createUserAssociation(newAssociationKey, user1Domain,
                        user1Tenant, username1WithoutDomain);
                UserAccountAssociationDAO.getInstance().createUserAssociation(newAssociationKey, user2Domain,
                        user2Tenant, username2WithoutDomain);

            } else if (validAssociationKey && !validConnUserAssociationKey) {
                UserAccountAssociationDAO.getInstance().createUserAssociation(associationKey, user2Domain,
                        user2Tenant, username2WithoutDomain);

            } else if (!validAssociationKey && validConnUserAssociationKey) {
                UserAccountAssociationDAO.getInstance().createUserAssociation(connUserAssociationKey, user1Domain,
                        user1Tenant, username1WithoutDomain);

            } else {
                UserAccountAssociationDAO.getInstance().updateUserAssociationKey(connUserAssociationKey,
                        associationKey);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(INVALID_INPUTS.getDescription());

            }
            throw handleUserAccountAssociationClientException(INVALID_INPUTS, null, true);
        }

    }

    public void createUserAccountAssociation(String userName, char[] password) throws
            UserAccountAssociationException {


        String tenantDomain = MultitenantUtils.getTenantDomain(userName);
        String loggedInUser = UserCoreUtil.addTenantDomainToEntry(CarbonContext.getThreadLocalCarbonContext()
                .getUsername(), CarbonContext.getThreadLocalCarbonContext().getTenantDomain());

        org.wso2.carbon.user.api.UserRealm userRealm;
        RealmService realmService;
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
        int tenantId;
        try {
            realmService = IdentityAccountAssociationServiceComponent.getRealmService();
            tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            throw handleUserAccountAssociationClientException(ERROR_WHILE_GETTING_TENANT_ID, e, false);
        } catch (Exception e) {
            throw handleUserAccountAssociationClientException(ERROR_WHILE_LOADING_REALM_SERVICE, e, false);
        }

        if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
            if (log.isDebugEnabled()) {
                log.debug(String.format(UserAccountAssociationConstants.ErrorMessages.DEBUG_INVALID_TENANT_DOMAIN
                        .getDescription(), tenantDomain));
            }
            throw handleUserAccountAssociationClientException(INVALID_TENANT_DOMAIN, null, true);
        }

        if (!CarbonContext.getThreadLocalCarbonContext().getTenantDomain().equals(tenantDomain)) {
            throw handleUserAccountAssociationClientException(ATTEMPTED_CROSS_TENANT_ASSOCIATION, null, false);
        }

        boolean authentic;
        try {
            userRealm = realmService.getTenantUserRealm(tenantId);
            authentic = userRealm.getUserStoreManager().authenticate(tenantAwareUsername, String.valueOf(password));
            userName = UserCoreUtil.addDomainToName(userName, UserCoreUtil.getDomainFromThreadLocal());
        } catch (UserStoreException e) {
            throw handleUserAccountAssociationClientException(ERROR_WHILE_AUTHENTICATING_USER, e, false);
        }

        if (!authentic) {
            if (log.isDebugEnabled()) {
                log.debug(USER_NOT_AUTHENTIC.getDescription());

            }
            throw handleUserAccountAssociationClientException(USER_NOT_AUTHENTIC, null, true);
        }

        UserAccountConnectorImpl.getInstance().createUserAccountAssociation(loggedInUser, userName);
    }

    /**
     * Delete an existing user account association
     *
     * @param userName Username of account to delete associations of.
     * @throws org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException
     */
    @Override
    public void deleteUserAccountAssociation(String userName) throws UserAccountAssociationException {

        if (!StringUtils.isBlank(userName)) {

            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
            int tenantId = MultitenantConstants.INVALID_TENANT_ID;
            RealmService realmService;

            try {
                realmService = IdentityAccountAssociationServiceComponent.getRealmService();
                tenantId = realmService.getTenantManager().getTenantId(MultitenantUtils.getTenantDomain(userName));
            } catch (UserStoreException e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_GETTING_TENANT_ID, e, false);
            } catch (Exception e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_LOADING_REALM_SERVICE, e, false);
            }

            if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format(UserAccountAssociationConstants.ErrorMessages.DEBUG_INVALID_TENANT_DOMAIN
                            .getDescription(), MultitenantUtils.getTenantDomain(userName)));
                }
                throw handleUserAccountAssociationClientException(INVALID_TENANT_DOMAIN, null, true);
            }

            String domainName = IdentityUtil.extractDomainFromName(tenantAwareUsername);
            tenantAwareUsername = UserAccountAssociationUtil.getUsernameWithoutDomain(tenantAwareUsername);

            UserAccountAssociationDAO.getInstance().deleteUserAssociation(domainName, tenantId, tenantAwareUsername);

        } else {
            if (log.isDebugEnabled()) {
                log.debug(INVALID_INPUTS.getDescription());

            }
            throw handleUserAccountAssociationClientException(INVALID_INPUTS, null, true);
        }
    }

    @Override
    public void deleteAssociatedUserAccount(String ownerUserName, String associatedUserName)
            throws UserAccountAssociationException {

        if (isOwnerHasAValidAssociation(ownerUserName, associatedUserName)) {
            deleteUserAccountAssociation(associatedUserName);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("The user: " + ownerUserName + ", does not have a valid association with the user: "
                        + associatedUserName + ", to proceed with the deletion of the association");
            }
            throw handleUserAccountAssociationClientException(INVALID_ASSOCIATION, null, true);
        }
    }

    /**
     * Get all associated accounts of the logged in user
     *
     * @param userName Username to get account list of
     * @return
     * @throws UserAccountAssociationException
     */
    @Override
    public UserAccountAssociationDTO[] getAccountAssociationsOfUser(String userName) throws
            UserAccountAssociationException {

        String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(userName);
        String tenantDomain = MultitenantUtils.getTenantDomain(userName);
        RealmService realmService;
        int tenantId;

        try {
            realmService = IdentityAccountAssociationServiceComponent.getRealmService();
            tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            throw handleUserAccountAssociationServerException(ERROR_WHILE_GETTING_TENANT_ID, e, false);
        } catch (Exception e) {
            throw handleUserAccountAssociationServerException(ERROR_WHILE_LOADING_REALM_SERVICE, e, false);
        }
        List<UserAccountAssociationDTO> userAccountAssociations = UserAccountAssociationDAO.getInstance()
                .getAssociationsOfUser(
                        IdentityUtil.extractDomainFromName(tenantAwareUserName),
                        tenantId, UserCoreUtil.removeDomainFromName(tenantAwareUserName));

        if (!userAccountAssociations.isEmpty()) {
            return userAccountAssociations.toArray(new UserAccountAssociationDTO[userAccountAssociations.size()]);
        }
        return new UserAccountAssociationDTO[0];
    }

    /**
     * Switch logged in user account to the required associated user account
     *
     * @param userName Username of associated account to switch
     * @return
     * @throws org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException
     */
    @Override
    public boolean switchLoggedInUser(String userName) throws UserAccountAssociationException {

        if (!StringUtils.isBlank(userName)) {

            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(userName);
            String tenantDomain = MultitenantUtils.getTenantDomain(userName);
            String domainName = IdentityUtil.extractDomainFromName(tenantAwareUsername);
            tenantAwareUsername = UserAccountAssociationUtil.getUsernameWithoutDomain(tenantAwareUsername);
            RealmService realmService;
            int tenantId = MultitenantConstants.INVALID_TENANT_ID;

            try {
                realmService = IdentityAccountAssociationServiceComponent.getRealmService();
                tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_GETTING_TENANT_ID, e, false);
            } catch (Exception e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_LOADING_REALM_SERVICE, e, false);
            }

            if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format(UserAccountAssociationConstants.ErrorMessages.DEBUG_INVALID_TENANT_DOMAIN
                            .getDescription(), MultitenantUtils.getTenantDomain(userName)));
                }
                throw handleUserAccountAssociationClientException(INVALID_TENANT_DOMAIN, null, true);
            }

            if (!UserAccountAssociationDAO.getInstance().isValidUserAssociation(domainName, tenantId,
                    tenantAwareUsername)) {
                if (log.isDebugEnabled()) {
                    log.debug(INVALID_ASSOCIATION.getDescription());
                }
                throw handleUserAccountAssociationClientException(INVALID_ASSOCIATION, null, true);
            }

            try {

                if (!realmService.getTenantManager().isTenantActive(tenantId)) {
                    log.warn("Tenant has been deactivated. TenantID : " + tenantId);
                    return false;
                }

                MessageContext msgCtx = MessageContext.getCurrentMessageContext();
                HttpServletRequest request = (HttpServletRequest) msgCtx.getProperty(HTTPConstants
                        .MC_HTTP_SERVLETREQUEST);
                HttpSession httpSession = request.getSession();
                String remoteAddress = AuthenticationUtil.getRemoteAddress(msgCtx);
                UserRealm userRealm = realmService.getTenantUserRealm(tenantId);

                if (!UserAccountAssociationConstants.PRIMARY_USER_DOMAIN.equals(domainName)) {
                    tenantAwareUsername = domainName + CarbonConstants.DOMAIN_SEPARATOR + tenantAwareUsername;
                }

                // Only pre and post authentication listeners will get executed,
                // as user is already authenticated during the account association creation phase
                boolean isAuthenticated = UserAccountAssociationUtil.executePrePostAuthenticationListeners
                        (tenantAwareUsername, (org.wso2.carbon.user.core.UserStoreManager) userRealm
                                .getUserStoreManager());

                boolean isAuthorized = userRealm.getAuthorizationManager().isUserAuthorized
                        (tenantAwareUsername, UserAccountAssociationConstants.LOGIN_PERMISSION, CarbonConstants
                                .UI_PERMISSION_ACTION);

                if (isAuthenticated && isAuthorized) {
                    CarbonAuthenticationUtil.onSuccessAdminLogin(httpSession, tenantAwareUsername, tenantId,
                            tenantDomain, remoteAddress);
                    audit.info(getAuditMessage(true, CarbonContext.getThreadLocalCarbonContext().getUsername(),
                            CarbonContext.getThreadLocalCarbonContext().getTenantId(),
                            tenantAwareUsername, tenantId, tenantDomain));
                    return true;
                } else {
                    LoginAttempt loginAttempt =
                            new LoginAttempt(tenantAwareUsername, tenantId, remoteAddress, new Date(), false,
                                    "unauthorized");
                    LoginStatDatabase.recordLoginAttempt(loginAttempt);
                    audit.warn(getAuditMessage(false, CarbonContext.getThreadLocalCarbonContext().getUsername
                                    (), CarbonContext.getThreadLocalCarbonContext().getTenantId(),
                            tenantAwareUsername, tenantId, tenantDomain));
                }
            } catch (org.wso2.carbon.user.core.UserStoreException e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_UPDATING_SESSION, e, false);
            } catch (UserStoreException e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_ACCESSING_REALM_SERVICE, e, false);
            } catch (AuthenticationException e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_RETRIEVING_REMOTE_ADDRESS, e, false);
            } catch (Exception e) {
                throw handleUserAccountAssociationServerException(ERROR_WHILE_EXECUTING_AUTHENTICATORS, e, false);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug(INVALID_INPUTS.getDescription());
            }
            throw handleUserAccountAssociationClientException(INVALID_INPUTS, null, true);
        }

        return false;
    }

    /**
     * Get audit message for on success or fail of switching
     *
     * @param success
     * @param loggedInUser
     * @param loggedInTenant
     * @param userName
     * @param tenantId
     * @param tenantDomain
     * @return
     */
    private String getAuditMessage(boolean success, String loggedInUser, int loggedInTenant, String userName,
                                   int tenantId, String tenantDomain) {

        Date currentTime = Calendar.getInstance().getTime();
        SimpleDateFormat date = new SimpleDateFormat("'['yyyy-MM-dd HH:mm:ss,SSSZ']'");

        if (success) {
            return "\'" + loggedInUser + "\' [" + loggedInTenant + "] switched to \'" + userName
                    + "@" + tenantDomain + " [" + tenantId + "]\' successfully at " + date.format(currentTime);
        }
        return "Failed to switch from \'" + loggedInUser + "\' [" + loggedInTenant + "] to \'"
                + userName + "@" + tenantDomain + " [" + tenantId + "]\' at " + date.format(currentTime);
    }

    private UserAccountAssociationClientException handleUserAccountAssociationClientException
            (UserAccountAssociationConstants.ErrorMessages errorMessages, Throwable throwable, boolean
                    messageWithCode) {

        String message;
        if (messageWithCode) {
            message = errorMessages.toString();
        } else {
            message = errorMessages.getDescription();
        }

        if (throwable == null) {
            return new UserAccountAssociationClientException(String.valueOf(errorMessages.getCode()), message);
        } else {
            return new UserAccountAssociationClientException(String.valueOf(errorMessages.getCode()), message, throwable);
        }
    }

    private UserAccountAssociationServerException handleUserAccountAssociationServerException
            (UserAccountAssociationConstants.ErrorMessages errorMessages, Throwable throwable, boolean
                    messageWithCode) {

        String message;
        if (messageWithCode) {
            message = errorMessages.toString();
        } else {
            message = errorMessages.getDescription();
        }

        if (throwable == null) {
            return new UserAccountAssociationServerException(String.valueOf(errorMessages.getCode()), message);
        } else {
            return new UserAccountAssociationServerException(String.valueOf(errorMessages.getCode()), message, throwable);
        }
    }

    private void logWarnMessage(String userName1, String userName2, boolean user1Exists, boolean user2Exists) {

        StringBuilder errorMsg = new StringBuilder("User association failed due to the following " +
                "user/users does not exist in the system. \n");
        if (!user1Exists) {
            errorMsg.append(" - user: ");
            errorMsg.append(userName1);
        }

        if (!user2Exists) {
            errorMsg.append(" - user: ");
            errorMsg.append(userName2);
        }
        log.warn(errorMsg);
    }

    private boolean isOwnerHasAValidAssociation(String ownerUserName, String associatedUserName)
            throws UserAccountAssociationException {

        boolean isOwnerHasValidAssociation = false;
        User associatedUser = getAssociatedUser(associatedUserName);
        for (UserAccountAssociationDTO eachUserAccountAssociation : getAccountAssociationsOfUser(ownerUserName)) {
            if (isSameAsTheAssociatedUser(associatedUser, eachUserAccountAssociation)) {
                isOwnerHasValidAssociation = true;
            }
        }
        return isOwnerHasValidAssociation;
    }

    private boolean isSameAsTheAssociatedUser(User associatedUser, UserAccountAssociationDTO userAccountAssociation) {

        return userAccountAssociation.getTenantDomain().equals(associatedUser.getTenantDomain())
                && userAccountAssociation.getDomain().equals(associatedUser.getUserStoreDomain())
                && userAccountAssociation.getUsername().equals(associatedUser.getUserName());
    }

    private User getAssociatedUser(String associatedUserName) {

        String tenantDomain = MultitenantUtils.getTenantDomain(associatedUserName);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(associatedUserName);

        String tenantAwareUserName = MultitenantUtils.getTenantAwareUsername(associatedUserName);
        String userName = UserCoreUtil.removeDomainFromName(tenantAwareUserName);

        User associatedUser = new User();
        associatedUser.setUserName(userName);
        associatedUser.setUserStoreDomain(userStoreDomain);
        associatedUser.setTenantDomain(tenantDomain);
        return associatedUser;
    }
}
