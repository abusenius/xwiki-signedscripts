/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.crypto.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.InstantiationStrategy;
import org.xwiki.component.descriptor.ComponentInstantiationStrategy;
import org.xwiki.component.logging.AbstractLogEnabled;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.crypto.KeyManager;
import org.xwiki.crypto.data.XWikiCertificate;
import org.xwiki.crypto.data.XWikiKeyPair;


/**
 * Default implementation of the {@link KeyManager}.
 * 
 * @version $Id$
 * @since 2.5
 */
@Component
@InstantiationStrategy(ComponentInstantiationStrategy.SINGLETON)
public class DefaultKeyManager extends AbstractLogEnabled implements KeyManager, Initializable
{
    /** Algorithm to use when generating keys. */
    private static final String KEY_ALGORITHM = "RSA";

    /** The algorithm to use for signing certificates. */
    private static final String SIGN_ALGORITHM = "SHA1withRSA";

    /** Signing algorithm key size in bits. */
    private static final int KEY_SIZE = 2048;

    /** Key pair generator. */
    private KeyPairGenerator kpGen;

    /** Fingerprint of the local root certificate. */
    private String localRootFingerprint;

    /** Global root certificate. */
    private XWikiCertificate globalRootCertificate;

    /** FIXME. */
    private Map<String, XWikiCertificate> certMap = new HashMap<String, XWikiCertificate>(); 

    /** FIXME. */
    private Map<String, XWikiKeyPair> keysMap = new HashMap<String, XWikiKeyPair>();

    /**
     * {@inheritDoc}
     * @see org.xwiki.component.phase.Initializable#initialize()
     */
    public void initialize() throws InitializationException
    {
        Security.addProvider(new BouncyCastleProvider());
        try {
            kpGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            kpGen.initialize(KEY_SIZE);
        } catch (GeneralSecurityException exception) {
            getLogger().debug(exception.getMessage(), exception);
            throw new InitializationException("Failed to initialize key pair generator.", exception);
        }
        // FIXME read local and global root certs
        // FIXME DEBUG
        try {
            regenerateLocalRoot();
            String globalFp = createKeyPair("XWiki.org", null);
            this.globalRootCertificate = getCertificate(globalFp);
            unregister(globalFp);
            registerCertificate(globalRootCertificate);
        } catch (GeneralSecurityException exception) {
            getLogger().debug(exception.getMessage(), exception);
            throw new InitializationException(exception.getMessage(), exception);
        }
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#createKeyPair(java.lang.String, java.util.Date)
     */
    public String createKeyPair(String authorName, Date expires) throws GeneralSecurityException
    {
        KeyPair kp = this.kpGen.generateKeyPair();

        // TODO rights and actions
        // local root certificate might not be present if we are generating it, default to self-signed
        X500Principal author = new X500Principal("CN=" + authorName);
        X500Principal issuer = author;
        PrivateKey signKey = kp.getPrivate();
        String signFingerprint = null;
        if (this.localRootFingerprint != null) {
            XWikiCertificate signCert = getLocalRootCertificate();
            issuer = signCert.getCertificate().getSubjectX500Principal();
            signKey = getLocalRootKeyPair().getPrivateKey();
            signFingerprint = signCert.getFingerprint();
        }

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSubjectDN(author);
        certGen.setIssuerDN(issuer);
        certGen.setSerialNumber(new BigInteger(128, new SecureRandom()));

        certGen.setNotBefore(new Date());
        if (expires != null) {
            certGen.setNotAfter(expires);
        } else {
            Date now = new Date();
            long year = 1000 * 3600 * 24 * 365;
            certGen.setNotAfter(new Date(now.getTime() + year * 25));
        }

        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm(SIGN_ALGORITHM);

        XWikiCertificate cert = new XWikiCertificate(certGen.generate(signKey), signFingerprint, this);
        String fingerprint = cert.getFingerprint();
        XWikiKeyPair keys = new XWikiKeyPair(kp.getPrivate(), cert);
        this.certMap.put(fingerprint, cert);
        this.keysMap.put(fingerprint, keys);
        return fingerprint;
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#getCertificate(java.lang.String)
     */
    public XWikiCertificate getCertificate(String fingerprint) throws GeneralSecurityException
    {
        XWikiCertificate cert = this.certMap.get(fingerprint);
        if (cert == null) {
            throw new GeneralSecurityException("Certificate with fingerprint \"" + fingerprint + "\" not found");
        }
        return cert;
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#getKeyPair(java.lang.String)
     */
    public XWikiKeyPair getKeyPair(String fingerprint) throws GeneralSecurityException
    {
        XWikiKeyPair kp = this.keysMap.get(fingerprint);
        if (kp == null) {
            throw new GeneralSecurityException("Key pair with fingerprint \"" + fingerprint + "\" was not found");
        }
        return kp;
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#registerCertificate(org.xwiki.crypto.data.XWikiCertificate)
     */
    public void registerCertificate(XWikiCertificate certificate) throws GeneralSecurityException
    {
        this.certMap.put(certificate.getFingerprint(), certificate);
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#unregister(java.lang.String)
     */
    public void unregister(String fingerprint) throws GeneralSecurityException
    {
        String localFingerprint = getLocalRootCertificate().getFingerprint();
        this.certMap.remove(fingerprint);
        this.keysMap.remove(fingerprint);
        if (localFingerprint.equals(fingerprint)) {
            regenerateLocalRoot();
        }
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#parseCertificate(java.lang.String)
     */
    public XWikiCertificate parseCertificate(String encoded) throws GeneralSecurityException
    {
        return new XWikiCertificate(XWikiCertificate.x509FromString(encoded), null, this);
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#getLocalRootCertificate()
     */
    public XWikiCertificate getLocalRootCertificate()
    {
        return getLocalRootKeyPair().getCertificate();
    }

    /**
     * {@inheritDoc}
     * @see org.xwiki.crypto.KeyManager#getGlobalRootCertificate()
     */
    public XWikiCertificate getGlobalRootCertificate()
    {
        return this.globalRootCertificate;
    }

    /**
     * Generate a new key pair and replace the local root certificate with it.
     * 
     * @throws GeneralSecurityException on errors
     */
    private void regenerateLocalRoot() throws GeneralSecurityException
    {
        this.certMap.remove(this.localRootFingerprint);
        this.keysMap.remove(this.localRootFingerprint);
        this.localRootFingerprint = null;
        this.localRootFingerprint = createKeyPair("Local Root", null);
    }

    /**
     * Get the local root key pair.
     * 
     * @return local root key pair object
     */
    private XWikiKeyPair getLocalRootKeyPair()
    {
        try {
            return getKeyPair(this.localRootFingerprint);
        } catch (GeneralSecurityException exception) {
            getLogger().debug(exception.getMessage(), exception);
            throw new RuntimeException("Should not happen: " + exception.getMessage(), exception);
        }
    }
}

