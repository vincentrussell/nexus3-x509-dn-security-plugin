package com.github.vincentrussell.nexus3.x509.dn.security.plugin;

import org.apache.commons.io.IOUtils;
import org.apache.shiro.authc.x509.X509AuthenticationInfo;
import org.apache.shiro.authc.x509.X509AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class X509DnAuthenticatingRealmTest {

    public static final String DEFAULT_DN = "CN=Firstname Lastname, OU=Unknown, O=Unknown, L=Annapolis Junction, ST=MD, C=US";
    public static final String SECOND_DN = "CN=Firstname Lastname2, OU=Unknown, O=Unknown, L=Annapolis Junction, ST=MD, C=US";
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    File configFile;

    @Before
    public void writeConfigFile() throws IOException {
        configFile = temporaryFolder.newFile();
        try (FileOutputStream fileOutputStream = new FileOutputStream(configFile)) {
            IOUtils.write("" +
                    "nx-admin:\n" +
                    "    - CN=Firstname Lastname, OU=Unknown, O=Unknown, L=Annapolis Junction, ST=MD, C=US\n" +
                    "nx-deploy:\n" +
                    "    - CN=Firstname Lastname, OU=Unknown, O=Unknown, L=Annapolis Junction, ST=MD, C=US \n" +
                    "    - CN=Firstname Lastname2, OU=Unknown, O=Unknown, L=Annapolis Junction, ST=MD, C=US    ", fileOutputStream);
        }
    }

    @After
    public void clearSystemProperty() {
        System.getProperties().remove(X509DnAuthenticatingRealm.CONFIG_FILE);
    }

    @Test(expected = IllegalStateException.class)
    public void missingConfigFile() {
        new X509DnAuthenticatingRealm();
    }

    @Test(expected = IllegalStateException.class)
    public void corruptedConfigFile() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        try (FileOutputStream fileOutputStream = new FileOutputStream(configFile)) {
            IOUtils.write("" +
                    "fsasdf" +
                    "asdfdsaf a  " +
                    "dafdsf ", fileOutputStream);
            new X509DnAuthenticatingRealm();
        }

    }

    @Test(expected = IllegalStateException.class)
    public void unparseableYaml() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        try (FileOutputStream fileOutputStream = new FileOutputStream(configFile)) {
            IOUtils.write("nx-admin:\n" +
                    "            * user\n", fileOutputStream);
            new X509DnAuthenticatingRealm();
        }

    }

    @Test
    public void parsesProperty() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        new X509DnAuthenticatingRealm();

    }

    @Test
    public void processX509AuthenticationToken() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        X509DnAuthenticatingRealm realm = new X509DnAuthenticatingRealm();
        X509AuthenticationToken token = getToken(DEFAULT_DN);
        X509AuthenticationInfo result = realm.doGetX509AuthenticationInfo(token);
        assertEquals("CN=Firstname Lastname,OU=Unknown,O=Unknown,L=Annapolis Junction,ST=MD,C=US",
                result.getSubjectDN().getName());
    }

    @Test
    public void processPrincipalCollectionDefault() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        X509DnAuthenticatingRealm realm = new X509DnAuthenticatingRealm();
        PrincipalCollection principalCollection = getPrincipalCollection(DEFAULT_DN);
        AuthorizationInfo result = realm.doGetAuthorizationInfo(principalCollection);
        assertThat(result.getRoles(), hasItems("nx-admin", "nx-deploy"));
    }

    @Test
    public void dnsAreNormalizedWhenGettingRoles() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        X509DnAuthenticatingRealm realm = new X509DnAuthenticatingRealm();
        PrincipalCollection principalCollection = getPrincipalCollection("CN=Firstname Lastname,     OU=Unknown,    O=Unknown,    L=Annapolis Junction,   ST=MD,   C=US");
        AuthorizationInfo result = realm.doGetAuthorizationInfo(principalCollection);
        assertThat(result.getRoles(), hasItems("nx-admin", "nx-deploy"));
    }

    @Test
    public void processPrincipalCollectionOnlyOne() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        X509DnAuthenticatingRealm realm = new X509DnAuthenticatingRealm();
        PrincipalCollection principalCollection = getPrincipalCollection(SECOND_DN);
        AuthorizationInfo result = realm.doGetAuthorizationInfo(principalCollection);
        assertThat(result.getRoles(), hasItems("nx-deploy"));
    }

    @Test
    public void processPrincipalCollectionNotFound() throws IOException {
        System.setProperty(X509DnAuthenticatingRealm.CONFIG_FILE, configFile.getAbsolutePath());
        X509DnAuthenticatingRealm realm = new X509DnAuthenticatingRealm();
        PrincipalCollection principalCollection = getPrincipalCollection("CN=Firstname Lastname3,     OU=Unknown,    O=Unknown,    L=Annapolis Junction,   ST=MD,   C=US");
        AuthorizationInfo result = realm.doGetAuthorizationInfo(principalCollection);
        assertThat(result.getRoles(), hasItems("nx-anonymous"));
    }

    private X509AuthenticationToken getToken(String name)  {
        X509AuthenticationToken token = mock(X509AuthenticationToken.class);
        X500Principal x500Principal = new X500Principal(name);
        when(token.getSubjectDN()).thenReturn(x500Principal);
        return token;
    }

    private PrincipalCollection getPrincipalCollection(String name)  {
       return new SimplePrincipalCollection(name, X509DnAuthenticatingRealm.NAME);
    }

}
