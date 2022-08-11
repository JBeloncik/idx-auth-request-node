package com.daon.idxAuthRequestNode;

import org.forgerock.openam.auth.node.api.NodeProcessException;

import com.identityx.clientSDK.TenantRepoFactory;
import com.identityx.clientSDK.credentialsProviders.EncryptedKeyPropFileCredentialsProvider;
import com.identityx.clientSDK.credentialsProviders.ADCredentialsProvider;
import com.identityx.clientSDK.def.ICredentialsProvider;
import com.identityx.clientSDK.exceptions.ClientInitializationException;
import com.identityx.clientSDK.exceptions.IdxRestException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

class IdxTenantRepoFactorySingleton {

	private static LoggerWrapper logger = new LoggerWrapper();
	
    private static IdxTenantRepoFactorySingleton tenantRepoInstance = null;

    public TenantRepoFactory tenantRepoFactory = null;

    private IdxTenantRepoFactorySingleton(String tenantUrl, String username, String password) throws NodeProcessException {
        
    	logger.info("Entering IdxTenantRepoFactorySingleton");
        
        
		ICredentialsProvider credentialProvider = null;
		
		try {
			credentialProvider = new ADCredentialsProvider(tenantUrl, username, password);

			tenantRepoFactory = new TenantRepoFactory.TenantRepoFactoryBuilder()
                                .setCredentialsProvider(credentialProvider)
                                .setCreateBrowserSession(false)
                                .build();
		} catch(IdxRestException ex) {
			logger.error("IdxTenantRepoFactorySingleton Exception", ex);
			throw new NodeProcessException("FATAL: ", ex);
		}
        
        logger.info("Exiting IdxTenantRepoFactorySingleton");
    }

    static IdxTenantRepoFactorySingleton getInstance(String tenantUrl, String username, String password) throws NodeProcessException {
    	logger.info("Entering getInstance");
    	
        if(tenantRepoInstance == null) {
        	logger.debug("TenantRepoFactory is null, creating new instance");
            tenantRepoInstance = new IdxTenantRepoFactorySingleton(tenantUrl, username, password);
        }
        
        logger.info("Exiting getInstance");
        return tenantRepoInstance;
    }
    
    private InputStream getFileStream(String filePath) {
    	
    	logger.info("Entering getFileStream");
    	
    	logger.debug("Attempt to get from ClassPath [{}]", filePath);
    	ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    	
    	InputStream stream = null;
    	
    	stream = classLoader.getResourceAsStream(filePath);
    	
    	if (stream == null) {
    		logger.warn("File does not exist on ClassPath");
    		logger.debug("Attempt to get from File System [{}]", filePath);
    		
    		File file = new File(filePath);
    		
    		if (file.exists() && file.isFile()) {
    			try {
    				stream = new FileInputStream(file);
    				logger.debug("Stream Created from File located on File System ");
				} catch (FileNotFoundException ex) {
					logger.warn("{}", ex.getMessage());
				}
    		} else {
    			logger.warn("File does not exist on File System");
    		}
    	} else {
    		logger.debug("Stream Created from File on ClassPath");
    	}
    	
    	logger.info("Exiting getFileStream");
    	return stream;
    }
}
