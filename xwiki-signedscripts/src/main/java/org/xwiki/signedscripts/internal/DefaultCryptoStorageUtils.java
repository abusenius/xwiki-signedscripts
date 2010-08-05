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
package org.xwiki.signedscripts.internal;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import org.xwiki.bridge.DocumentAccessBridge;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.Requirement;
import org.xwiki.crypto.x509.XWikiX509Certificate;
import org.xwiki.crypto.x509.XWikiX509KeyPair;
import org.xwiki.crypto.x509.internal.DefaultXWikiX509KeyPair;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.ObjectReference;


/**
 * Default implementation of {@link CryptoStorageUtils}. This class uses objects to store 
 * 
 * @version $Id$
 * @since 2.5
 */
@Component
public class DefaultCryptoStorageUtils implements CryptoStorageUtils
{
    /** The name of the XClass which represents a user's certificate. */
    private final String certClassName = "XWiki.X509CertificateClass";

    /** The name of the XClass which represents a user's key pair. */
    private final String keyClassName = "XWiki.X509KeyPairClass";

    /** The name of the property in the certificate XClass where the certificate fingerprint is stored. */
    private final String certFingerprintPropertyName = "fingerprint";

    /** The name of the property in the certificate XClass where the issuer fingerprint is stored. */
    private final String certIssuerFPPropertyName = "issuerFingerprint";

    /** The name of the property in the certificate XClass where the certificate in PEM format is stored. */
    private final String certCertificatePropertyName = "certificate";

    /** The name of the property in the key pair XClass where the key pair fingerprint is stored. */
    private final String keyFingerprintPropertyName = "finger" + "print";

    /** The name of the property in the key pair XClass where the encrypted key pair is stored. */
    private final String keyPairPropertyName = "keyPair";

    /** DocumentAccessBridge for getting the current user's document and URL. */
    @Requirement
    private DocumentAccessBridge bridge;

    /** Resolver which can make a DocumentReference out of a String. */
    @Requirement(role = String.class)
    private DocumentReferenceResolver<String> resolver;

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#getCertificateFingerprintsForUser(java.lang.String)
     */
    public List<String> getCertificateFingerprintsForUser(final String userName)
    {
        List<String> list = getStringPropertyList(userName, this.certClassName, this.certFingerprintPropertyName);
        // remove null values from the list
        List<String> filtered = new ArrayList<String>();
        for (String fp : list) {
            if (fp != null) {
                filtered.add(fp);
            }
        }
        return filtered;
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#addCertificate(java.lang.String, org.xwiki.crypto.x509.XWikiX509Certificate)
     */
    public void addCertificate(String userName, XWikiX509Certificate certificate) throws GeneralSecurityException
    {
        ObjectReference certObject = getObjectReference(userName, this.certClassName);
        try {
            int idx = this.bridge.addObject(certObject);
            this.bridge.setProperty(certObject, idx, this.certFingerprintPropertyName, certificate.getFingerprint());
            this.bridge.setProperty(certObject, idx, this.certIssuerFPPropertyName, certificate.getIssuerFingerprint());
            this.bridge.setProperty(certObject, idx, this.certCertificatePropertyName, certificate.toPEMString());
        } catch (Exception exception) {
            throw new GeneralSecurityException(exception);
        }
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#getUserCertificate(java.lang.String, java.lang.String)
     */
    public XWikiX509Certificate getUserCertificate(String userName, String fingerprint) throws GeneralSecurityException
    {
        // relies on {@link getStringPropertyList(String, String, String)} leaving certificates in correct order
        List<String> list = getStringPropertyList(userName, this.certClassName, this.certFingerprintPropertyName);
        int idx = list.indexOf(fingerprint);
        if (idx < 0) {
            return null;
        }
        ObjectReference certObject = getObjectReference(userName, this.certClassName);
        String certPEM = (String) this.bridge.getProperty(certObject, idx, this.certCertificatePropertyName);
        return XWikiX509Certificate.fromPEMString(certPEM);
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#getKeyPairFingerprintsForUser(java.lang.String)
     */
    public List<String> getKeyPairFingerprintsForUser(String userName)
    {
        List<String> list = getStringPropertyList(userName, this.keyClassName, this.keyFingerprintPropertyName);
        // remove null values from the list
        List<String> filtered = new ArrayList<String>();
        for (String fp : list) {
            if (fp != null) {
                filtered.add(fp);
            }
        }
        return filtered;
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#addKeyPair(java.lang.String, org.xwiki.crypto.x509.XWikiX509KeyPair)
     */
    public void addKeyPair(String userName, XWikiX509KeyPair keyPair) throws GeneralSecurityException
    {
        ObjectReference keyObject = getObjectReference(userName, this.keyClassName);
        try {
            int idx = this.bridge.addObject(keyObject);
            this.bridge.setProperty(keyObject, idx, this.keyFingerprintPropertyName, keyPair.getFingerprint());
            this.bridge.setProperty(keyObject, idx, this.keyPairPropertyName, keyPair.serializeAsBase64());
        } catch (Exception exception) {
            throw new GeneralSecurityException(exception);
        }
        addCertificate(userName, keyPair.getCertificate());
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#removeFingerprint(java.lang.String, java.lang.String)
     */
    public boolean removeFingerprint(String userDocument, String fingerprint) throws GeneralSecurityException
    {
        boolean result = removeObjects(userDocument, this.keyClassName, this.keyFingerprintPropertyName, fingerprint);
        return removeObjects(userDocument, this.certClassName, this.certFingerprintPropertyName, fingerprint)
                || result;
    }

    /**
     * Remove all objects having the given property set to the given value.
     * 
     * @param documentName name of the document where the objects are stored
     * @param className XWiki class name of the object
     * @param propName the property name
     * @param value the value to look for
     * @return true if some objects were removed, false otherwise
     * @throws GeneralSecurityException on errors
     */
    private boolean removeObjects(String documentName, String className, String propName, String value)
        throws GeneralSecurityException
    {
        // relies on {@link getStringPropertyList(String, String, String)} leaving properties in correct order
        ObjectReference object = getObjectReference(documentName, className);
        List<String> list = getStringPropertyList(documentName, className, propName);
        int index = 0;
        boolean removed = false;
        try {
            for (String fp : list) {
                if (fp != null && fp.equals(value)) {
                    removed |= this.bridge.removeObject(object, index);
                }
                index++;
            }
        } catch (Exception exception) {
            throw new GeneralSecurityException(exception);
        }
        return removed;
    }

    /**
     * {@inheritDoc}
     * 
     * @see org.xwiki.crypto.internal.UserDocumentUtils#getUserKeyPair(java.lang.String, java.lang.String, java.lang.String)
     */
    public XWikiX509KeyPair getUserKeyPair(String userName, String fingerprint, String password)
        throws GeneralSecurityException
    {
        // relies on {@link getStringPropertyList(String, String, String)} leaving keys in correct order
        List<String> list = getStringPropertyList(userName, this.keyClassName, this.keyFingerprintPropertyName);
        int idx = list.indexOf(fingerprint);
        if (idx < 0) {
            return null;
        }
        ObjectReference keyObject = getObjectReference(userName, this.keyClassName);
        String keyBase64 = (String) this.bridge.getProperty(keyObject, idx, this.keyPairPropertyName);
        try {
            return DefaultXWikiX509KeyPair.fromBase64String(keyBase64);
        } catch (Exception exception) {
            throw new GeneralSecurityException(exception);
        }
    }

    /**
     * Get a list of the property values present in all class objects found in the given document, in order of
     * occurrence, including null values for deleted objects.
     * 
     * @param document the document containing the objects 
     * @param className XClass name of the objects
     * @param propertyName property name to retrieve
     * @return a list of property values (may contain null values)
     */
    private List<String> getStringPropertyList(String document, String className, String propertyName)
    {
        DocumentReference documentReference = this.resolver.resolve(document);
        ObjectReference objectReference = new ObjectReference(className, documentReference);
        int count = this.bridge.getObjectCount(objectReference);
        List<String> out = new ArrayList<String>(count);
        for (int index = 0; index < count; index++) {
            // NOTE the value may be null (if some objects were deleted for example)
            out.add((String) this.bridge.getProperty(objectReference, index, propertyName));
        }
        return out;
    }

    /**
     * Get an object reference to an object of the given class in the user document. 
     * 
     * @param userName name of the user document where the object should be stored
     * @param className name of XWiki class of the object
     * @return object reference to the given object
     */
    private ObjectReference getObjectReference(String userName, String className)
    {
        DocumentReference userDocReference = this.resolver.resolve(userName);
        ObjectReference certObject = new ObjectReference(className, userDocReference);
        return certObject;
    }
}

