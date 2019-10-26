/*
 * Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 * under the License.
 *
 *
 */

package org.wso2.carbon.identity.user.account.association.handler.grant;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.user.account.association.UserAccountConnectorImpl;
import org.wso2.carbon.identity.user.account.association.dto.UserAccountAssociationDTO;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException;

import java.util.Arrays;
import java.util.HashSet;

public class AccountSwitchGrantHandler extends AbstractAuthorizationGrantHandler {

    private static final Log log = LogFactory.getLog(AccountSwitchGrantHandler.class);

    public static final String TOKEN_PARAM = "token";
    public static final String USERNAME_PARAM = "username";
    public static final String USERSTORE_DOMAIN_PARAM = "userstore-domain";
    public static final String TENANT_DOMAIN_PARAM = "tenant-domain";
    private final String OAUTH_HEADER = "Bearer";
    private final String ACCOUNT_SWITCH_TOKEN_VALIDATION_CONTEXT = "accountSwitchTokenValidationContext";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        super.validateGrant(tokReqMsgCtx);

        String token = extractParameter(TOKEN_PARAM, tokReqMsgCtx);;
        String username = extractParameter(USERNAME_PARAM, tokReqMsgCtx);;
        String userstoreDomain = extractParameter(USERSTORE_DOMAIN_PARAM, tokReqMsgCtx);;
        String tenantDomain = extractParameter(TENANT_DOMAIN_PARAM, tokReqMsgCtx);;

        if (StringUtils.isEmpty(token) || StringUtils.isEmpty(username) || StringUtils.isEmpty(username) ||
                StringUtils.isEmpty(username)) {
            if (log.isDebugEnabled()) {
                log.debug("Grant validation failed. Missing required parameters.");
            }
            ResponseHeader responseHeader = new ResponseHeader();
            responseHeader.setKey("error-description");
            responseHeader.setValue("Missing required parameters");
            tokReqMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});

            return false;
        }

        OAuth2TokenValidationResponseDTO validationResponseDTO = validateToken(token);
        tokReqMsgCtx.addProperty(ACCOUNT_SWITCH_TOKEN_VALIDATION_CONTEXT, validationResponseDTO);

        if (!validationResponseDTO.isValid()) {
            if (log.isDebugEnabled()) {
                log.debug("Access token validation failed.");
            }
            ResponseHeader responseHeader = new ResponseHeader();
            responseHeader.setKey("error-description");
            responseHeader.setValue("Missing required parameters");
            tokReqMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});

            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Access token validation success.");
        }

        User authorizedUser = User.getUserFromUserName(validationResponseDTO.getAuthorizedUser());

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

        tokReqMsgCtx.setAuthorizedUser(
                OAuth2Util.getUserFromUserName(associatedUser.toFullQualifiedUsername()));

        String[] allowedScopes =  getAllowedScopes(validationResponseDTO.getScope(),
                tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());
        tokReqMsgCtx.setScope(allowedScopes);

        if (log.isDebugEnabled()) {
            log.debug("Issuing an access token for associated user: " + associatedUser + " with scopes: " +
                    tokReqMsgCtx.getScope());
        }

        return true;
    }

    private String extractParameter(String param, OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        for (RequestParameter parameter : parameters) {
            if (param.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    return parameter.getValue()[0];
                }
            }
        }

        return null;
    }

    private String[] getAllowedScopes(String[] authorizedScoped, String[] requestedScopes) {

        HashSet<String> allowedScopesSet = new HashSet<>();
        allowedScopesSet.addAll(Arrays.asList(authorizedScoped));
        allowedScopesSet.retainAll(Arrays.asList(requestedScopes));

        if (log.isDebugEnabled()) {
            log.debug("Allowed scopes: " + allowedScopesSet);
        }

        String[] allowedScopes = {};
        allowedScopes = allowedScopesSet.toArray(allowedScopes);
        return allowedScopes;
    }

    private boolean validateAssociation(User user, User associatedUser) throws UserAccountAssociationException {

        UserAccountAssociationDTO[] userAccountAssociationDTOS =
                UserAccountConnectorImpl.getInstance().getAccountAssociationsOfUser(user.toFullQualifiedUsername());
        if (userAccountAssociationDTOS != null) {
            for (UserAccountAssociationDTO userAccountAssociationDTO : userAccountAssociationDTOS) {

                if (userAccountAssociationDTO.getTenantDomain().equals(associatedUser.getTenantDomain())) {
                    if (userAccountAssociationDTO.getDomain().equals(associatedUser.getUserStoreDomain())) {
                        if (userAccountAssociationDTO.getUsername().equals(associatedUser.getUserName())) {
                            return true;
                        }
                    }
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
        token.setTokenType(OAUTH_HEADER);
        requestDTO.setAccessToken(token);

        //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
        OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                TokenValidationContextParam();
        contextParam.setKey("dummy");
        contextParam.setValue("dummy");

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams =
                new OAuth2TokenValidationRequestDTO.TokenValidationContextParam[1];
        contextParams[0] = contextParam;
        requestDTO.setContext(contextParams);

        OAuth2ClientApplicationDTO clientApplicationDTO = oAuth2TokenValidationService
                .findOAuthConsumerIfTokenIsValid
                        (requestDTO);
        OAuth2TokenValidationResponseDTO responseDTO = clientApplicationDTO.getAccessTokenValidationResponse();
        return responseDTO;
    }

}
