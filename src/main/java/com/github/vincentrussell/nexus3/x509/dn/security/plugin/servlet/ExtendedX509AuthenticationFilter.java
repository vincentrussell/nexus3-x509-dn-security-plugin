package com.github.vincentrussell.nexus3.x509.dn.security.plugin.servlet;

import com.github.vincentrussell.nexus3.x509.dn.security.plugin.X509DnAuthenticatingRealm;
import com.github.vincentrussell.nexus3.x509.dn.security.plugin.api.ExtendedX509AuthenticationToken;
import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.web.filter.authc.X509AuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;


@Named
@Singleton
public class ExtendedX509AuthenticationFilter extends X509AuthenticationFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger( ExtendedX509AuthenticationFilter.class );
    public static final String NAME = "ExtendedX509AuthenticationFilter";
    private final RealmSecurityManager realmSecurityManager;

    @Inject
    public ExtendedX509AuthenticationFilter(RealmSecurityManager realmSecurityManager) {
        this.realmSecurityManager = realmSecurityManager;
    }

    @Override
    protected boolean onAccessDenied( ServletRequest request, ServletResponse response )
            throws Exception
    {
        if (getClientCertChain(request)[0].getSubjectDN()
                .equals(X509DnAuthenticatingRealm.DEFAULT_ANONYMOUS_CERT.getSubjectDN())) {
            return true;
        }
        return executeLogin( request, response );
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response)
            throws Exception {
        X509Certificate[] clientCertChain = getClientCertChain(request);
        LOGGER.info("X509AuthFilter.createToken() cert chain is {}", clientCertChain);
        return new ExtendedX509AuthenticationToken(clientCertChain, getHost(request));
    }

    private X509Certificate[] getClientCertChain(ServletRequest request) throws CertificateException, IOException {
        X509Certificate[] clientCertChain = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (clientCertChain == null || clientCertChain.length < 1) {
            clientCertChain = new X509Certificate[]{X509DnAuthenticatingRealm.DEFAULT_ANONYMOUS_CERT};
            LOGGER.info("X509AuthFilter.createToken() cert chain is not found, using anonymous cert");
        }
        return clientCertChain;
    }

    @Override
    public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        List<Class> realmClasses = Lists.newArrayList(Iterables.transform(this.realmSecurityManager.getRealms(), new Function<Object, Class>() {
            @Override
            public Class apply(Object input) {
                return input.getClass();
            }
        }));

        if (realmClasses.contains(X509DnAuthenticatingRealm.class)) {
            filterInternalForX509Realm(request, response, chain);
        } else {
            skipThisFilterAndContinueOnChain(request, response, chain);
        }
    }

    private void skipThisFilterAndContinueOnChain(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        Exception exception = null;
        try {
            executeChain(request, response, chain);
        } catch (Exception e) {
            exception = e;
        } finally {
            cleanup(request, response, exception);
        }
    }

    private void filterInternalForX509Realm(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        super.doFilterInternal(request,response,chain);
    }

}
