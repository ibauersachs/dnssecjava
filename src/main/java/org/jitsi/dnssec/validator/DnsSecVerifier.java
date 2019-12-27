/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * 
 * This file is based on work under the following copyright and permission
 * notice:
 * 
 *     Copyright (c) 2005 VeriSign. All rights reserved.
 * 
 *     Redistribution and use in source and binary forms, with or without
 *     modification, are permitted provided that the following conditions are
 *     met:
 * 
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *     3. The name of the author may not be used to endorse or promote
 *        products derived from this software without specific prior written
 *        permission.
 * 
 *     THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *     IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *     ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 *     INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *     (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *     SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *     STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *     IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *     POSSIBILITY OF SUCH DAMAGE.
 */

package org.jitsi.dnssec.validator;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * A class for performing basic DNSSEC verification. The DNSJAVA package
 * contains a similar class. This is a reimplementation that allows us to have
 * finer control over the validation process.
 * 
 * @author davidb
 */
public class DnsSecVerifier {
    private static final Logger logger = LoggerFactory.getLogger(DnsSecVerifier.class);

    /**
     * Find the matching DNSKEY(s) to an RRSIG within a DNSKEY rrset. Normally
     * this will only return one DNSKEY. It can return more than one, since
     * KeyID/Footprints are not guaranteed to be unique.
     * 
     * @param dnskeyRrset The DNSKEY rrset to search.
     * @param signature The RRSIG to match against.
     * @return A List contains a one or more DNSKEYRecord objects, or null if a
     *         matching DNSKEY could not be found.
     */
    private List<DNSKEYRecord> findKey(RRset dnskeyRrset, RRSIGRecord signature) {
        if (!signature.getSigner().equals(dnskeyRrset.getName())) {
            logger.trace("findKey: could not find appropriate key because incorrect keyset was supplied. Wanted: "
                    + signature.getSigner() + ", got: " + dnskeyRrset.getName());
            return null;
        }

        int keyid = signature.getFootprint();
        int alg = signature.getAlgorithm();
        List<DNSKEYRecord> res = new ArrayList<>(dnskeyRrset.size());
        for (Record r : dnskeyRrset.rrs()) {
            DNSKEYRecord dnskey = (DNSKEYRecord)r;
            if (dnskey.getAlgorithm() == alg && dnskey.getFootprint() == keyid) {
                res.add(dnskey);
            }
        }

        if (res.size() == 0) {
            logger.trace("findKey: could not find a key matching the algorithm and footprint in supplied keyset. ");
            return null;
        }

        return res;
    }

    /**
     * Verify an RRset against a particular signature.
     * 
     * @param rrset The RRset to verify.
     * @param sigrec The signature record that signs the RRset.
     * @param keyRrset The keys used to create the signature record.
     * @param date The date against which to verify the signature.
     * 
     * @return {@link SecurityStatus#SECURE} if the signature verified,
     *         {@link SecurityStatus#BOGUS} if it did not verify (for any
     *         reason), and {@link SecurityStatus#UNCHECKED} if verification
     *         could not be completed (usually because the public key was not
     *         available).
     */
    private SecurityStatus verifySignature(SRRset rrset, RRSIGRecord sigrec,
                                           RRset keyRrset, Instant date) {
        List<DNSKEYRecord> keys = this.findKey(keyRrset, sigrec);
        if (keys == null) {
            logger.trace("could not find appropriate key");
            return SecurityStatus.BOGUS;
        }

        SecurityStatus status = SecurityStatus.UNCHECKED;
        for (DNSKEYRecord key : keys) {
            try {
                if (!rrset.getName().subdomain(keyRrset.getName())) {
                    logger.debug("signer name is off-tree");
                    status = SecurityStatus.BOGUS;
                    continue;
                }

                DNSSEC.verify(rrset, sigrec, key, date);
                ValUtils.setCanonicalNsecOwner(rrset, sigrec);
                return SecurityStatus.SECURE;
            }
            catch (DNSSECException e) {
                logger.error("Failed to validate RRset {}/{}", rrset.getName(), Type.string(rrset.getType()), e);
                status = SecurityStatus.BOGUS;
            }
        }

        return status;
    }

    /**
     * Verifies an RRset. This routine does not modify the RRset. This RRset is
     * presumed to be verifiable, and the correct DNSKEY rrset is presumed to
     * have been found.
     * 
     * @param rrset The RRset to verify.
     * @param keyRrset The keys to verify the signatures in the RRset to check.
     * @param date The date against which to verify the rrset.
     * @return SecurityStatus.SECURE if the rrest verified positively,
     *         SecurityStatus.BOGUS otherwise.
     */
    public SecurityStatus verify(SRRset rrset, RRset keyRrset, Instant date) {
        List<RRSIGRecord> sigs = rrset.sigs();
        if (sigs.isEmpty()) {
            logger.info("RRset failed to verify due to lack of signatures");
            return SecurityStatus.BOGUS;
        }

        for (RRSIGRecord sigrec : sigs) {
            SecurityStatus res = this.verifySignature(rrset, sigrec, keyRrset, date);
            if (res == SecurityStatus.SECURE) {
                return res;
            }
        }

        logger.info("RRset failed to verify: all signatures were BOGUS");
        return SecurityStatus.BOGUS;
    }

    /**
     * Verify an RRset against a single DNSKEY. Use this when you must be
     * certain that an RRset signed and verifies with a particular DNSKEY (as
     * opposed to a particular DNSKEY rrset).
     * 
     * @param rrset The rrset to verify.
     * @param dnskey The DNSKEY to verify with.
     * @param date The date against which to verify the rrset.
     * @return SecurityStatus.SECURE if the rrset verified, BOGUS otherwise.
     */
    public SecurityStatus verify(RRset rrset, DNSKEYRecord dnskey, Instant date) {
        List<RRSIGRecord> sigs = rrset.sigs();
        if (sigs.isEmpty()) {
            logger.info("RRset failed to verify due to lack of signatures");
            return SecurityStatus.BOGUS;
        }

        for (RRSIGRecord sigrec : sigs) {
            // Skip RRSIGs that do not match our given key's footprint.
            if (sigrec.getFootprint() != dnskey.getFootprint()) {
                continue;
            }

            try {
                DNSSEC.verify(rrset, sigrec, dnskey, date);
                return SecurityStatus.SECURE;
            }
            catch (DNSSECException e) {
                logger.error("Failed to validate RRset", e);
            }
        }

        logger.info("RRset failed to verify: all signatures were BOGUS");
        return SecurityStatus.BOGUS;
    }
}
