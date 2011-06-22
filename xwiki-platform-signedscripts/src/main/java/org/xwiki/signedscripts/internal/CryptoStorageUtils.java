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
import java.util.List;

import org.xwiki.component.annotation.ComponentRole;
import org.xwiki.crypto.x509.XWikiX509Certificate;
import org.xwiki.crypto.x509.XWikiX509KeyPair;


/**
 * An internal component used to store, load and modify certificates and key pairs stored in XWiki documents.
 * 
 * @version $Id$
 * @since 2.5
 */
@ComponentRole
public interface CryptoStorageUtils
{
    /**
     * Get a list of XWikiX509Certificate fingerprints for the named user.
     *
     * @param userName the string representation of the document reference for the user document.
     * @return A list of all of this user's authorized certificate fingerprints.
     */
    List<String> getCertificateFingerprintsForUser(final String userName);

    /**
     * Add a certificate to the list of certificates of the given user.
     * 
     * @param userName reference to the user document
     * @param certificate the certificate to add
     * @throws GeneralSecurityException on errors
     */
    void addCertificate(String userName, XWikiX509Certificate certificate) throws GeneralSecurityException;

    /**
     * Get the certificate object from the data stored in user's profile by its fingerprint. Returns null if the given
     * fingerprint is not present in the list of user certificates ({@link #getCertificateFingerprintsForUser(String)})
     * 
     * @param userName name of the user who owns the certificate
     * @param fingerprint certificate fingerprint identifying the certificate to retrieve
     * @return the initialized certificate object
     * @throws GeneralSecurityException if the certificate data is invalid
     */
    XWikiX509Certificate getUserCertificate(String userName, String fingerprint) throws GeneralSecurityException;

    /**
     * Get a list of XWikiX509KeyPair fingerprints for the named user.
     *
     * @param userName the string representation of the document reference for the user document.
     * @return A list of all of this user's authorized key pair fingerprints.
     */
    List<String> getKeyPairFingerprintsForUser(String userName);

    /**
     * Add a key pair and the certificate it contains to the list of key pairs and certificates of the given user.
     * 
     * @param userName reference to the user document
     * @param keyPair the key pair to add
     * @throws GeneralSecurityException on errors
     */
    void addKeyPair(String userName, XWikiX509KeyPair keyPair) throws GeneralSecurityException;

    /**
     * Get the key pair object from the data stored in user's profile by its fingerprint. Returns null if the given
     * fingerprint is not present in the list of user key pairs ({@link #getKeyPairFingerprintsForUser(String)})
     * 
     * @param userName name of the user who owns the certificate
     * @param fingerprint key pair fingerprint identifying the key pair to retrieve
     * @param password the password to use for decryption
     * @return the initialized key pair object
     * @throws GeneralSecurityException if the key pair data is invalid
     */
    XWikiX509KeyPair getUserKeyPair(String userName, String fingerprint, String password)
        throws GeneralSecurityException;

    /**
     * Remove the certificate and/or key pair with the given fingerprint for the user document.
     * 
     * @param userDocument name of the target user document
     * @param fingerprint fingerprint of the certificate or key pair to remove
     * @return true on success, false otherwise
     * @throws GeneralSecurityException if the document cannot be accessed
     */
    boolean removeFingerprint(String userDocument, String fingerprint) throws GeneralSecurityException;
}
