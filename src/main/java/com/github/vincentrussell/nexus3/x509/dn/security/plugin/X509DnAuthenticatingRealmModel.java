package com.github.vincentrussell.nexus3.x509.dn.security.plugin;

import com.github.vincentrussell.nexus3.x509.dn.security.plugin.servlet.ExtendedX509AuthenticationFilter;
import com.google.inject.AbstractModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.internal.security.SecurityModule;
import org.sonatype.nexus.rapture.internal.RaptureModule;
import org.sonatype.nexus.security.FilterChainModule;
import org.sonatype.nexus.security.FilterProviderSupport;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import static org.sonatype.nexus.security.FilterProviderSupport.filterKey;

@Named
public class X509DnAuthenticatingRealmModel  extends AbstractModule {

    @Override
    protected void configure() {

        bind(filterKey(ExtendedX509AuthenticationFilter.NAME)).to(ExtendedX509AuthenticationFilter.class);
        bind(filterKey(ExtendedX509AuthenticationFilter.NAME)).toProvider(ExtendedX509AuthenticationFilterProvider.class);


        install(new SecurityModule());
        install(new RaptureModule());

       install(new FilterChainModule() {
            @Override
            protected void configure() {
                addFilterChain("/**",
                        ExtendedX509AuthenticationFilter.NAME);
            }
        });

    }

    @Singleton
    static class ExtendedX509AuthenticationFilterProvider
            extends FilterProviderSupport
    {
        @Inject
        ExtendedX509AuthenticationFilterProvider(final ExtendedX509AuthenticationFilter filter) {
                super(filter);
        }
    }

}
