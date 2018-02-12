package com.github.vincentrussell.nexus3.x509.dn.security.plugin;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import org.apache.shiro.authc.x509.X509AuthenticationInfo;
import org.apache.shiro.authc.x509.X509AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.x509.AbstractX509Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.anonymous.AnonymousPrincipalCollection;
import org.sonatype.nexus.security.internal.AuthenticatingRealmImpl;
import org.yaml.snakeyaml.Yaml;

import javax.inject.Named;
import javax.inject.Singleton;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.util.*;

/**
 * The Class X509DnAuthenticatingRealm.
 */
@Singleton
@Named(AuthenticatingRealmImpl.NAME)
@Description("X509-Dn Authenticating Realm")
public class X509DnAuthenticatingRealm extends AbstractX509Realm {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509DnAuthenticatingRealm.class);
    protected static final String NAME = "NexusAuthenticatingRealm";
    protected static final String CONFIG_FILE = X509DnAuthenticatingRealm.class.getSimpleName() + ".config.file";
    public static final SimpleAuthorizationInfo ANONYMOUS_AUTHORIZATION_INFO = new SimpleAuthorizationInfo(Sets.newHashSet("nx-anonymous"));
    private final Yaml yaml = new Yaml();
    private final Multimap<String, String> roleToDnMultimap = HashMultimap.create();
    private final Multimap<String, String> dnToRoleMultimap = HashMultimap.create();

    public X509DnAuthenticatingRealm() {
        try (FileInputStream fileInputStream = new FileInputStream(System.getProperty(CONFIG_FILE))) {
            Map<String, List<String>> compiledYaml = yaml.load(fileInputStream);
            generateMultiMaps(compiledYaml);
        } catch (Throwable e) {
            throw new IllegalStateException(e);
        }
        setAuthenticationTokenClass(X509AuthenticationToken.class);
        setName(NAME);
        setAuthenticationCachingEnabled(true);
    }

    private void generateMultiMaps(Map<String, List<String>> compiledYaml) {
        for (Map.Entry<String, List<String>>  entry : compiledYaml.entrySet()) {
            String role = entry.getKey();
            for (String dn : entry.getValue()) {
                String normalizedDn = normalizeDn(dn);
                dnToRoleMultimap.put(normalizedDn, role);
                roleToDnMultimap.put(normalizedDn, dn);
            }
        }
    }

    private String normalizeDn(String dn) {
        X500Principal x500Principal = new X500Principal(dn);
        return x500Principal.getName();
    }


    @Override
    protected X509AuthenticationInfo doGetX509AuthenticationInfo(X509AuthenticationToken x509AuthenticationToken) {
        final String dn = x509AuthenticationToken.getSubjectDN().getName();
        LOGGER.info("dn received: {}", dn);
        X509AuthenticationInfo x509AuthenticationInfo = new X509AuthenticationInfo(dn, x509AuthenticationToken.getSubjectDN(), NAME);
        x509AuthenticationInfo.setCredentials(dn);
        return x509AuthenticationInfo;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        if (AnonymousPrincipalCollection.class.isInstance(principals)) {
            return ANONYMOUS_AUTHORIZATION_INFO;
        }
        String normalizeDn = normalizeDn((String) principals.getPrimaryPrincipal());
        Set<String> roles = new HashSet<>();
        Collection<String> potentialRoles = dnToRoleMultimap.get(normalizeDn);

        if (potentialRoles == null || potentialRoles.size() == 0) {
            return ANONYMOUS_AUTHORIZATION_INFO;
        }

        roles.addAll(potentialRoles);
        return new SimpleAuthorizationInfo(roles);
    }

}
