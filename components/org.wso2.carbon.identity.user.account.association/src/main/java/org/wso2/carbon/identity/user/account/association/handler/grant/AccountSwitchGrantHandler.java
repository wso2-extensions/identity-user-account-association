/*
 * Copyright (c) 2015-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.user.account.association.handler.grant;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.user.account.association.UserAccountConnectorImpl;
import org.wso2.carbon.identity.user.account.association.dto.UserAccountAssociationDTO;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException;
import org.wso2.carbon.identity.user.account.association.internal.IdentityAccountAssociationServiceComponent;
import org.wso2.carbon.identity.user.account.association.internal.IdentityAccountAssociationServiceDataHolder;
import org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.AccountSwitchGrant;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Arrays;
import java.util.HashSet;

import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_RESOLVING_TENANT_DOMAIN;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_RESOLVING_USER_ID;
import static org.wso2.carbon.identity.user.account.association.util.UserAccountAssociationConstants.ErrorMessages.ERROR_WHILE_RESOLVING_USER_NAME;

/**
 * Implements the AuthorizationGrantHandler for the AccountSwitchGrant Type : account-switch.
 */
public class AccountSwitchGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(AccountSwitchGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);

        String token = extractParameter(AccountSwitchGrant.Params.TOKEN_PARAM, tokReqMsgCtx);
        String username = extractParameter(AccountSwitchGrant.Params.USERNAME_PARAM, tokReqMsgCtx);
        String userstoreDomain = extractParameter(AccountSwitchGrant.Params.USERSTORE_DOMAIN_PARAM, tokReqMsgCtx);
        String tenantDomain = extractParameter(AccountSwitchGrant.Params.TENANT_DOMAIN_PARAM, tokReqMsgCtx);

        OAuth2TokenValidationResponseDTO validationResponseDTO = validateToken(token);

        if (!validationResponseDTO.isValid()) {
            if (log.isDebugEnabled()) {
                log.debug("Access token validation failed.");
            }

            throw new IdentityOAuth2Exception("Invalid token received.");
        }

        if (log.isDebugEnabled()) {
            log.debug("Access token validation success.");
        }

        User authorizedUser = User.getUserFromUserName(validationResponseDTO.getAuthorizedUser());
        AccessTokenDO accessTokenDO = OAuth2Util.findAccessToken(token, false);
        if (isSubOrganizationUser(accessTokenDO)) {
            String authorizedUserName = resolveUserName(accessTokenDO.getAuthzUser().getUserResidentOrganization(),
                    MultitenantUtils.getTenantAwareUsername(accessTokenDO.getAuthzUser().getUserName()));
            authorizedUser.setUserName(authorizedUserName);
            authorizedUser.setTenantDomain(
                    resolveTenantDomain(accessTokenDO.getAuthzUser().getUserResidentOrganization()));
        }

        User associatedUser = new User();
        associatedUser.setUserName(username);
        associatedUser.setUserStoreDomain(userstoreDomain);
        associatedUser.setTenantDomain(tenantDomain);

        boolean isValidAssociation = false;
        try {
            isValidAssociation = validateAssociation(authorizedUser, associatedUser);
        } catch (UserAccountAssociationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while validating associations", e);
            }
        }

        if (!isValidAssociation) {
            if (log.isDebugEnabled()) {
                log.debug("Authorized user: " + authorizedUser.toFullQualifiedUsername() + " not associated to: " +
                        associatedUser.toFullQualifiedUsername());
            }
            ResponseHeader responseHeader = new ResponseHeader();
            responseHeader.setKey("error-description");
            responseHeader.setValue("Associated user is invalid.");
            tokReqMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});

            return false;
        }
        AuthenticatedUser authenticatedUser = OAuth2Util.getUserFromUserName(associatedUser.toFullQualifiedUsername());
        if (isSubOrganizationUser(accessTokenDO)) {
            authenticatedUser.setAccessingOrganization(accessTokenDO.getAuthzUser().getAccessingOrganization());
            authenticatedUser.setUserResidentOrganization(accessTokenDO.getAuthzUser().getUserResidentOrganization());
            authenticatedUser.setFederatedUser(true);
            authenticatedUser.setFederatedIdPName(accessTokenDO.getAuthzUser().getFederatedIdPName());
            authenticatedUser.setTenantDomain(accessTokenDO.getAuthzUser().getTenantDomain());
            String userId = getUserId(username, tenantDomain);
            authenticatedUser.setUserId(userId);
            authenticatedUser.setUserName(userId + "@" + accessTokenDO.getAuthzUser().getUserResidentOrganization());
        }

        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        //This is commented to support account switching capability.
        //https://github.com/wso2/product-is/issues/7385
        //String[] allowedScopes =  getAllowedScopes(validationResponseDTO.getScope(),
        //tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        String[] allowedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        tokReqMsgCtx.setScope(allowedScopes);

        if (log.isDebugEnabled()) {
            log.debug("Issuing an access token for associated user: " + associatedUser + " with scopes: " +
                    tokReqMsgCtx.getScope());
        }

        return true;
    }

    private String extractParameter(String param, OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        if (parameters != null) {
            for (RequestParameter parameter : parameters) {
                if (param.equals(parameter.getKey())) {
                    if (ArrayUtils.isNotEmpty(parameter.getValue())) {
                        return parameter.getValue()[0];
                    }
                }
            }
        }

        return null;
    }

    private String[] getAllowedScopes(String[] authorizedScoped, String[] requestedScopes) {

        HashSet<String> allowedScopesSet = new HashSet<>();
        allowedScopesSet.addAll(Arrays.asList(ArrayUtils.nullToEmpty(authorizedScoped)));
        allowedScopesSet.retainAll(Arrays.asList(ArrayUtils.nullToEmpty(requestedScopes)));

        if (log.isDebugEnabled()) {
            log.debug("Allowed scopes: " + allowedScopesSet);
        }

        return allowedScopesSet.toArray(ArrayUtils.EMPTY_STRING_ARRAY);
    }

    private boolean validateAssociation(User user, User associatedUser) throws UserAccountAssociationException {

        UserAccountAssociationDTO[] userAccountAssociationDTOS =
                UserAccountConnectorImpl.getInstance().getAccountAssociationsOfUser(user.toFullQualifiedUsername());
        if (userAccountAssociationDTOS != null) {
            for (UserAccountAssociationDTO userAccountAssociationDTO : userAccountAssociationDTOS) {

                if (associatedUser.getTenantDomain().equals(userAccountAssociationDTO.getTenantDomain()) &&
                        associatedUser.getUserStoreDomain().equals(userAccountAssociationDTO.getDomain()) &&
                        associatedUser.getUserName().equals(userAccountAssociationDTO.getUsername())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Validate access token
     * @param accessToken
     * @return OAuth2TokenValidationResponseDTO of the validated token
     */
    private OAuth2TokenValidationResponseDTO validateToken(String accessToken) {

        OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
        OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();

        token.setIdentifier(accessToken);
        token.setTokenType("bearer");
        requestDTO.setAccessToken(token);

        //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                TokenValidationContextParam();
        contextParam.setKey("dummy");
        contextParam.setValue("dummy");

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = {contextParam};
        requestDTO.setContext(contextParams);

        OAuth2ClientApplicationDTO clientApplicationDTO = oAuth2TokenValidationService
                .findOAuthConsumerIfTokenIsValid
                        (requestDTO);
        OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();
        return responseDTO;
    }

    private String resolveUserName (String orgId, String userId) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = resolveTenantDomain(orgId);
            return OAuth2Util.resolveUsernameFromUserId(tenantDomain, userId);
        } catch (UserStoreException e) {
            throw new IdentityOAuth2Exception(String.valueOf(ERROR_WHILE_RESOLVING_USER_NAME.getCode()),
                    ERROR_WHILE_RESOLVING_USER_NAME.getDescription(), e);
        }
    }

    private String resolveTenantDomain(String orgId) throws IdentityOAuth2Exception {

        try {
            return getOrganizationManager().resolveTenantDomain(orgId);
        } catch (OrganizationManagementException e) {
            throw new IdentityOAuth2Exception(String.valueOf(ERROR_WHILE_RESOLVING_TENANT_DOMAIN.getCode()),
                    ERROR_WHILE_RESOLVING_TENANT_DOMAIN.getDescription(), e);
        }
    }

    private OrganizationManager getOrganizationManager() {

        return IdentityAccountAssociationServiceDataHolder.getInstance().getOrganizationManager();
    }

    private String getUserId(String userName, String tenantDomain) throws IdentityOAuth2Exception {

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            AbstractUserStoreManager userStoreManager = getAbstractUserStoreManager(tenantId);
            return userStoreManager.getUserIDFromUserName(userName);
        } catch (UserStoreException | UserAccountAssociationException e) {
            throw new IdentityOAuth2Exception(String.valueOf(ERROR_WHILE_RESOLVING_USER_ID.getCode()),
                    ERROR_WHILE_RESOLVING_USER_ID.getDescription(), e);
        }
    }

    private AbstractUserStoreManager getAbstractUserStoreManager(int tenantId)
            throws UserStoreException, UserAccountAssociationException {

        RealmService realmService = IdentityAccountAssociationServiceComponent.getRealmService();
        org.wso2.carbon.user.api.UserRealm tenantUserRealm = realmService.getTenantUserRealm(tenantId);
        return (AbstractUserStoreManager) tenantUserRealm.getUserStoreManager();
    }

    private boolean isSubOrganizationUser(AccessTokenDO accessTokenDO) {

        return accessTokenDO.getAuthzUser().isFederatedUser() &&
                accessTokenDO.getAuthzUser().getUserResidentOrganization() != null;
    }
}
