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
package org.wso2.carbon.identity.user.account.association.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.user.account.association.UserAccountConnector;
import org.wso2.carbon.identity.user.account.association.UserAccountConnectorImpl;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.listener.UserOperationEventListener;
import org.wso2.carbon.user.core.listener.UserStoreManagerListener;
import org.wso2.carbon.user.core.service.RealmService;
import java.util.Collection;
import java.util.Map;
import java.util.TreeMap;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;

@Component(
         name = "identity.user.account.association.component", 
         immediate = true)
public class IdentityAccountAssociationServiceComponent {

    private static final Log log = LogFactory.getLog(IdentityAccountAssociationServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {
        try {
            IdentityAccountAssociationServiceDataHolder.getInstance().setBundleContext(context.getBundleContext());
            ServiceRegistration userAccountConnectorSR = IdentityAccountAssociationServiceDataHolder.getInstance().getBundleContext().registerService(UserAccountConnector.class.getName(), UserAccountConnectorImpl.getInstance(), null);
            if (userAccountConnectorSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity user account association service component activated successfully.");
                }
            } else {
                log.error("Identity user account association service component activation failed.");
            }
            ServiceRegistration UserOptEventListenerSR = IdentityAccountAssociationServiceDataHolder.getInstance().getBundleContext().registerService(UserOperationEventListener.class.getName(), new UserOperationEventListenerImpl(), null);
            if (UserOptEventListenerSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity user account association - UserOperationEventListener registered.");
                }
            } else {
                log.error("Identity user account association - UserOperationEventListener could not be registered.");
            }
            ServiceRegistration tenantMgtListenerSR = IdentityAccountAssociationServiceDataHolder.getInstance().getBundleContext().registerService(TenantMgtListener.class.getName(), new TenantMgtListenerImpl(), null);
            if (tenantMgtListenerSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity user account association - TenantMgtListener registered.");
                }
            } else {
                log.error("Identity user account association - TenantMgtListener could not be registered.");
            }
            ServiceRegistration userStoreConfigEventSR = IdentityAccountAssociationServiceDataHolder.getInstance().getBundleContext().registerService(UserStoreConfigListener.class.getName(), new UserStoreConfigListenerImpl(), null);
            if (userStoreConfigEventSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity user account association - UserStoreConfigListener registered.");
                }
            } else {
                log.error("Identity user account association - UserStoreConfigListener could not be registered.");
            }
        } catch (Exception e) {
            log.error("Failed to activate identity account connector service component ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Identity account connector service component is deactivated ");
        }
    }

    @Reference(
             name = "user.realmservice.default", 
             service = org.wso2.carbon.user.core.service.RealmService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        IdentityAccountAssociationServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        IdentityAccountAssociationServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(
             name = "user.store.manager.listener.service", 
             service = org.wso2.carbon.user.core.listener.UserStoreManagerListener.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetUserStoreManagerListenerService")
    protected void setUserStoreManagerListenerService(UserStoreManagerListener userStoreManagerListenerService) {
        IdentityAccountAssociationServiceDataHolder.getInstance().setUserStoreManagerListenerCollection(null);
        if (IdentityAccountAssociationServiceDataHolder.getInstance().getUserStoreManagerListeners() == null) {
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserStoreManagerListeners(new TreeMap<Integer, UserStoreManagerListener>());
        }
        IdentityAccountAssociationServiceDataHolder.getInstance().putUserStoreManagerListener(userStoreManagerListenerService.getExecutionOrderId(), userStoreManagerListenerService);
    }

    protected void unsetUserStoreManagerListenerService(UserStoreManagerListener userStoreManagerListenerService) {
        if (userStoreManagerListenerService != null && IdentityAccountAssociationServiceDataHolder.getInstance().getUserStoreManagerListeners() != null) {
            IdentityAccountAssociationServiceDataHolder.getInstance().removeUserStoreManagerListener(userStoreManagerListenerService.getExecutionOrderId());
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserOperationEventListenerCollection(null);
        }
    }

    @Reference(
             name = "user.operation.event.listener.service", 
             service = org.wso2.carbon.user.core.listener.UserOperationEventListener.class, 
             cardinality = ReferenceCardinality.MULTIPLE, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetUserOperationEventListenerService")
    protected void setUserOperationEventListenerService(UserOperationEventListener userOperationEventListenerService) {
        IdentityAccountAssociationServiceDataHolder.getInstance().setUserOperationEventListenerCollection(null);
        if (IdentityAccountAssociationServiceDataHolder.getInstance().getUserOperationEventListeners() == null) {
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserOperationEventListeners(new TreeMap<Integer, UserOperationEventListener>());
        }
        IdentityAccountAssociationServiceDataHolder.getInstance().putUserOperationEventListener(userOperationEventListenerService.getExecutionOrderId(), userOperationEventListenerService);
    }

    protected void unsetUserOperationEventListenerService(UserOperationEventListener userOperationEventListenerService) {
        if (userOperationEventListenerService != null && IdentityAccountAssociationServiceDataHolder.getInstance().getUserOperationEventListeners() != null) {
            IdentityAccountAssociationServiceDataHolder.getInstance().removeUserOperationEventListener(userOperationEventListenerService.getExecutionOrderId());
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserOperationEventListenerCollection(null);
        }
    }

    public static RealmService getRealmService() throws UserAccountAssociationException {
        RealmService realmService = IdentityAccountAssociationServiceDataHolder.getInstance().getRealmService();
        if (realmService == null) {
            String msg = "System has not been started properly. Realm Service is null.";
            log.error(msg);
            throw new UserAccountAssociationException(msg);
        }
        return realmService;
    }

    public static Collection<UserStoreManagerListener> getUserStoreManagerListeners() {
        Map<Integer, UserStoreManagerListener> userStoreManagerListeners = IdentityAccountAssociationServiceDataHolder.getInstance().getUserStoreManagerListeners();
        Collection<UserStoreManagerListener> userStoreManagerListenerCollection = IdentityAccountAssociationServiceDataHolder.getInstance().getUserStoreManagerListenerCollection();
        if (userStoreManagerListeners == null) {
            userStoreManagerListeners = new TreeMap<>();
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserStoreManagerListeners(userStoreManagerListeners);
        }
        if (userStoreManagerListenerCollection == null) {
            userStoreManagerListenerCollection = userStoreManagerListeners.values();
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserStoreManagerListenerCollection(userStoreManagerListenerCollection);
        }
        return userStoreManagerListenerCollection;
    }

    public static Collection<UserOperationEventListener> getUserOperationEventListeners() {
        Map<Integer, UserOperationEventListener> userOperationEventListeners = IdentityAccountAssociationServiceDataHolder.getInstance().getUserOperationEventListeners();
        Collection<UserOperationEventListener> userOperationEventListenerCollection = IdentityAccountAssociationServiceDataHolder.getInstance().getUserOperationEventListenerCollection();
        if (userOperationEventListeners == null) {
            userOperationEventListeners = new TreeMap<>();
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserOperationEventListeners(userOperationEventListeners);
        }
        if (userOperationEventListenerCollection == null) {
            userOperationEventListenerCollection = userOperationEventListeners.values();
            IdentityAccountAssociationServiceDataHolder.getInstance().setUserOperationEventListenerCollection(userOperationEventListenerCollection);
        }
        return userOperationEventListenerCollection;
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
             name = "identityCoreInitializedEventService", 
             service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
    /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    @Reference(
            name = "organization.management.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManagementService")
    protected void setOrganizationManagementService(OrganizationManager organizationManager) {

        IdentityAccountAssociationServiceDataHolder.getInstance().setOrganizationManager(organizationManager);
        log.debug("Set Organization Management Service");
    }

    protected void unsetOrganizationManagementService(OrganizationManager organizationManager) {

        IdentityAccountAssociationServiceDataHolder.getInstance().setOrganizationManager(null);
        log.debug("Unset Organization Management Service");
    }
}

