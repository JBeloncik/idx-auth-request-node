/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

package com.daon.idxAuthRequestNode;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.plugins.PluginException;

/**
 * Definition of an <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/auth/node/api/AbstractNodeAmPlugin.html">AbstractNodeAmPlugin</a>. 
 * Implementations can use {@code @Inject} setters to get access to APIs 
 * available via Guice dependency injection. For example, if you want to add an SMS service on install, you 
 * can add the following setter:
 * <pre><code>
 * {@code @Inject}
 * public void setPluginTools(PluginTools tools) {
 *     this.tools = tools;
 * }
 * </code></pre>
 * So that you can use the addSmsService api to load your schema XML for example.
 * PluginTools javadoc may be found 
 * <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/plugins/PluginTools.html#addSmsService-java.io.InputStream-">here</a> 
 * <p>
 *     It can be assumed that when running, implementations of this class will be singleton instances.
 * </p>
 * <p>
 *     It should <i>not</i> be expected that the runtime singleton instances will be the instances on which
 *     {@link #onAmUpgrade(String, String)} will be called. Guice-injected properties will also <i>not</i> be populated
 *     during that method call.
 * </p>
 * <p>
 *     Plugins should <i>not</i> use the {@code ShutdownManager}/{@code ShutdownListener} API for handling shutdown, as
 *     the order of calling those listeners is not deterministic. The {@link #onShutdown()} method for all plugins will
 *     be called in the reverse order from the order that {@link #onStartup()} was called, with dependent plugins being
 *     notified after their dependencies for startup, and before them for shutdown.
 * </p>
 * @supported.all.api
 * @since AM 5.5.0
 */
public class IdxAuthRequestNodePlugin extends AbstractNodeAmPlugin {

	static String currentVersion = "1.4.0";
	
    /** 
     * Specify the Map of list of node classes that the plugin is providing. These will then be installed and
     *  registered at the appropriate times in plugin lifecycle.
     *
     * @return The list of node classes.
     */
	@Override
	protected Map<String, Iterable<? extends Class<? extends Node>>> getNodesByVersion() {
		return Collections.singletonMap(IdxAuthRequestNodePlugin.currentVersion, 
				Arrays.asList(IdxAuthRequestNode.class, IdxAuthStatusNode.class, IdxCheckEnrollmentStatus.class,
						 IdxSponsorUser.class, IdxMobileAuthRequestNode.class, IdxMobileValidateAuthRequestNode.class));
	}

    /** 
     * This method will be called when the version returned by {@link #getPluginVersion()} is higher than the
     * version already installed. This method will be called before the {@link #onStartup()} method.
     * 
     * No need to implement this untils there are multiple versions of your auth node.
     *
     * @param fromVersion The old version of the plugin that has been installed.
     */	
	@Override
	public void upgrade(String fromVersion) throws PluginException {
		
		//Force Upgrade of Nodes, requires changing currentVersion=
		pluginTools.upgradeAuthNode(IdxCheckEnrollmentStatus.class);
		pluginTools.upgradeAuthNode(IdxMobileAuthRequestNode.class);
		pluginTools.upgradeAuthNode(IdxMobileValidateAuthRequestNode.class);
		super.upgrade(fromVersion);
	}

    /** 
     * The plugin version. This must be in semver (semantic version) format.
     *
     * @return The version of the plugin.
     * @see <a href="https://www.osgi.org/wp-content/uploads/SemanticVersioning.pdf">Semantic Versioning</a>
     */
	@Override
	public String getPluginVersion() {
		return IdxAuthRequestNodePlugin.currentVersion;
	}
}
