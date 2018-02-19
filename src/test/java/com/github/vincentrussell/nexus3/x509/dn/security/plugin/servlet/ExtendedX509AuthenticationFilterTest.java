package com.github.vincentrussell.nexus3.x509.dn.security.plugin.servlet;

import com.github.vincentrussell.nexus3.x509.dn.security.plugin.X509DnAuthenticatingRealm;
import com.github.vincentrussell.nexus3.x509.dn.security.plugin.api.ExtendedX509AuthenticationToken;
import com.google.common.collect.Lists;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.objenesis.Objenesis;
import org.objenesis.ObjenesisStd;
import org.objenesis.instantiator.ObjectInstantiator;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.security.auth.x500.X500Principal;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.management.*", "javax.security.*"})
public class ExtendedX509AuthenticationFilterTest {

    private MockHttpServletRequest mockHttpServletRequest;
    private MockHttpServletResponse mockHttpServletResponse;
    private ExtendedX509AuthenticationFilter extendedX509AuthenticationFilter;
    private RealmSecurityManager realmSecurityManager;

    @Before
    public void setup() {
        realmSecurityManager = mock(RealmSecurityManager.class);
        mockHttpServletRequest = new MockHttpServletRequest();
        mockHttpServletResponse = new MockHttpServletResponse();
        extendedX509AuthenticationFilter = new ExtendedX509AuthenticationFilter(realmSecurityManager);
    }


    @Test
    public void createTokenExtendedX509AuthenticationToken() throws Exception {
        MockHttpServletRequest request = x509("keystore.cer").postProcessRequest(
                mockHttpServletRequest);
        AuthenticationToken token = extendedX509AuthenticationFilter.createToken(request, mockHttpServletResponse);
        assertTrue(ExtendedX509AuthenticationToken.class.isInstance(token));
        String dn = "CN=Firstname Lastname,OU=Unknown,O=Unknown,L=Annapolis Junction,ST=MD,C=US";
        assertEquals(dn, ((X500Principal)token.getPrincipal()).getName());
        assertEquals("localhost", ((ExtendedX509AuthenticationToken)token).getHost());
        assertEquals(dn,token.getCredentials());
    }


    @Test
    public void doFilterInternalWithX509RealmNotPresent() throws Exception {
        Objenesis objenesis = new ObjenesisStd();
        ObjectInstantiator X509DnAuthenticatingRealmInstantiator = objenesis.getInstantiatorOf(X509DnAuthenticatingRealm.class);
        X509DnAuthenticatingRealm x509DnAuthenticatingRealm = (X509DnAuthenticatingRealm) X509DnAuthenticatingRealmInstantiator.newInstance();
        FilterChain filterChain = mock(FilterChain.class);
        when(realmSecurityManager.getRealms()).thenReturn(Lists.newArrayList(x509DnAuthenticatingRealm));
        ExtendedX509AuthenticationFilter child = PowerMockito.spy(extendedX509AuthenticationFilter);
        PowerMockito.doNothing().when(child, "skipThisFilterAndContinueOnChain", eq(mockHttpServletRequest), eq(mockHttpServletResponse), eq(filterChain));
        child.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, filterChain);
        //PowerMockito.verifyPrivate(child, times(1)).invoke("filterInternalForX509Realm" , eq(mockHttpServletRequest), eq(mockHttpServletResponse), eq(filterChain));
        PowerMockito.verifyPrivate(child).invoke("skipThisFilterAndContinueOnChain" , mockHttpServletRequest, mockHttpServletResponse, filterChain);
    }

    @Test
    public void doFilterInternalWithX509RealmPresent() throws Exception {
        Objenesis objenesis = new ObjenesisStd();
        ObjectInstantiator X509DnAuthenticatingRealmInstantiator = objenesis.getInstantiatorOf(X509DnAuthenticatingRealm.class);
        X509DnAuthenticatingRealm x509DnAuthenticatingRealm = (X509DnAuthenticatingRealm) X509DnAuthenticatingRealmInstantiator.newInstance();
        FilterChain filterChain = mock(FilterChain.class);
        when(realmSecurityManager.getRealms()).thenReturn(Lists.newArrayList(x509DnAuthenticatingRealm));
        ExtendedX509AuthenticationFilter child = PowerMockito.spy(extendedX509AuthenticationFilter);
        PowerMockito.doNothing().when(child, "filterInternalForX509Realm", eq(mockHttpServletRequest), eq(mockHttpServletResponse), eq(filterChain));
        child.doFilterInternal(mockHttpServletRequest, mockHttpServletResponse, filterChain);
        PowerMockito.verifyPrivate(child).invoke("filterInternalForX509Realm" , mockHttpServletRequest, mockHttpServletResponse, filterChain);
    }




}
