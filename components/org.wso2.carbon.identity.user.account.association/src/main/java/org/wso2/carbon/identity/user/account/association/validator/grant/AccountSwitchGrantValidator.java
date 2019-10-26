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

package org.wso2.carbon.identity.user.account.association.validator.grant;

import org.apache.oltu.oauth2.common.validators.AbstractValidator;
import org.wso2.carbon.identity.user.account.association.handler.grant.AccountSwitchGrantHandler;

import javax.servlet.http.HttpServletRequest;

public class AccountSwitchGrantValidator extends AbstractValidator<HttpServletRequest> {

    public AccountSwitchGrantValidator() {

        // token must be in the request parameter
        requiredParams.add(AccountSwitchGrantHandler.TOKEN_PARAM);
        requiredParams.add(AccountSwitchGrantHandler.USERNAME_PARAM);
        requiredParams.add(AccountSwitchGrantHandler.USERSTORE_DOMAIN_PARAM);
        requiredParams.add(AccountSwitchGrantHandler.TENANT_DOMAIN_PARAM);
    }
}
