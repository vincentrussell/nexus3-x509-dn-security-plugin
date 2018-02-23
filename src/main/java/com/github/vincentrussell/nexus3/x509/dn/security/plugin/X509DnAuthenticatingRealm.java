package com.github.vincentrussell.nexus3.x509.dn.security.plugin;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import org.apache.shiro.authc.x509.X509AuthenticationInfo;
import org.apache.shiro.authc.x509.X509AuthenticationToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.x509.AbstractX509Realm;
import org.apache.shiro.subject.PrincipalCollection;
import org.eclipse.sisu.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.security.anonymous.AnonymousPrincipalCollection;
import org.yaml.snakeyaml.Yaml;

import javax.inject.Named;
import javax.inject.Singleton;
import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * The Class X509DnAuthenticatingRealm.
 */
@Singleton
@Named(X509DnAuthenticatingRealm.NAME)
@Description("X509-Dn Authenticating Realm")
public class X509DnAuthenticatingRealm extends AbstractX509Realm {

    private static final Logger LOGGER = LoggerFactory.getLogger(X509DnAuthenticatingRealm.class);

    private static String ALL_RESULTS = "ALL_RESULTS";

    public static final X509Certificate DEFAULT_ANONYMOUS_CERT = getDefaultAnonymousCert();
    protected static final String NAME = "X509DnAuthenticatingRealm";
    protected static final String CONFIG_FILE = X509DnAuthenticatingRealm.class.getSimpleName() + ".config.file";
    public static final SimpleAuthorizationInfo ANONYMOUS_AUTHORIZATION_INFO = new SimpleAuthorizationInfo(Sets.newHashSet("nx-anonymous"));

    private LoadingCache<String, LoadingCacheResult> certInfoAche = CacheBuilder.newBuilder()
            .maximumSize(1)
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .build(
                    new CacheLoader<String, LoadingCacheResult>() {
                        @Override
                        public LoadingCacheResult load(String id) throws Exception {
                            return new LoadingCacheResult();
                        }
                    }
            );

    private static X509Certificate getDefaultAnonymousCert() {
        try (InputStream inputStream = X509DnAuthenticatingRealm.class.getResourceAsStream("/certs/anonymous/anonymous.cer")) {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            final X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(inputStream);
            return certificate;
        } catch (Throwable e) {
            LOGGER.error(e.getMessage(), e);
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    public X509DnAuthenticatingRealm() {
        setAuthenticationTokenClass(X509AuthenticationToken.class);
        setName(NAME);
        setAuthenticationCachingEnabled(true);
        verifyConfigFile();
    }

    private void verifyConfigFile() {
        new LoadingCacheResult();
    }

    private static String normalizeDn(String dn) {
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
        Collection<String> potentialRoles = null;
        try {
            potentialRoles = certInfoAche.get(ALL_RESULTS).getDnToRoleMultimap().get(normalizeDn);
        } catch (ExecutionException e) {
            throw new AuthorizationException(e.getMessage(), e);
        }

        if (potentialRoles == null || potentialRoles.size() == 0) {
            return ANONYMOUS_AUTHORIZATION_INFO;
        }

        roles.addAll(potentialRoles);
        return new SimpleAuthorizationInfo(roles);
    }

    private static class LoadingCacheResult {
        private final Yaml yaml = new Yaml();
        private final Multimap<String, String> roleToDnMultimap = HashMultimap.create();
        private final Multimap<String, String> dnToRoleMultimap = HashMultimap.create();

        LoadingCacheResult() {
            try (FileInputStream fileInputStream = new FileInputStream(System.getProperty(CONFIG_FILE))) {
                Map<String, List<String>> compiledYaml = yaml.load(fileInputStream);
                generateMultiMaps(compiledYaml);
            } catch (Throwable e) {
                throw new IllegalStateException(e);
            }
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

        public Multimap<String, String> getRoleToDnMultimap() {
            return roleToDnMultimap;
        }

        public Multimap<String, String> getDnToRoleMultimap() {
            return dnToRoleMultimap;
        }
    }

}
