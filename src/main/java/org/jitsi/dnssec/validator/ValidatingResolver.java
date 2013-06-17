/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (C) 2013 Ingo Bauersachs. All rights reserved.
 *
 * This file is part of dnssecjava.
 *
 * Dnssecjava is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Dnssecjava is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with dnssecjava.  If not, see <http://www.gnu.org/licenses/>.
 * 
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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.jitsi.dnssec.DNSEvent;
import org.jitsi.dnssec.SMessage;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.jitsi.dnssec.Util;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Master;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * This resolver validates responses with DNSSEC.
 * 
 * @author davidb
 */
public class ValidatingResolver implements Resolver {
    private static final Logger logger = Logger.getLogger(ValidatingResolver.class);

    /**
     * This is the TTL to use when a trust anchor priming query failed to
     * validate.
     */
    private static final long DEFAULT_TA_BAD_KEY_TTL = 60;

    /**
     * This is a cache of validated, but expirable DNSKEY rrsets.
     */
    private KeyCache keyCache;

    /**
     * A data structure holding all trust anchors. Trust anchors must be
     * "primed" into the cache before being used to validate.
     */
    private TrustAnchorStore trustAnchors;

    /**
     * The local validation utilities.
     */
    private ValUtils valUtils;

    private Resolver headResolver;

    /**
     * Creates a new instance of this class.
     * 
     * @param headResolver The resolver to which queries for DS, DNSKEY and
     *            referring CNAME records are sent.
     */
    public ValidatingResolver(Resolver headResolver) {
        this.headResolver = headResolver;
        headResolver.setEDNS(0, 0, ExtendedFlags.DO, null);
        headResolver.setIgnoreTruncation(false);

        this.keyCache = new KeyCache();
        this.valUtils = new ValUtils();
        this.trustAnchors = new TrustAnchorStore();
    }

    // ---------------- Module Initialization -------------------
    /**
     * Initialize the module. The only recognized configuration value is
     * <tt>org.jitsi.dnssec.trust_anchor_file</tt>.
     * 
     * @param config The configuration data for this module.
     */
    public void init(Properties config) {
        this.keyCache.init(config);

        // Load trust anchors
        String s = config.getProperty("org.jitsi.dnssec.trust_anchor_file");
        if (s != null) {
            try {
                logger.debug("reading trust anchor file file: " + s);
                loadTrustAnchors(new FileInputStream(s));
            }
            catch (IOException e) {
                logger.error("Problems loading trust anchors from file", e);
            }
        }
    }

    /**
     * Load the trust anchor file into the trust anchor store. The trust anchors
     * are currently stored in a zone file format list of DNSKEY or DS records.
     * 
     * @param data The trust anchor data.
     * @throws IOException when the trust anchor data could not be read.
     */
    @SuppressWarnings("unchecked")
    public void loadTrustAnchors(InputStream data) throws IOException {
        // First read in the whole trust anchor file.
        Master master = new Master(data, Name.root, 0);
        List<Record> records = new ArrayList<Record>();
        Record r = null;

        while ((r = master.nextRecord()) != null) {
            records.add(r);
        }

        // Record.compareTo() should sort them into DNSSEC canonical order.
        // Don't care about canonical order per se, but do want them to be
        // formable into RRsets.
        Collections.sort(records);

        SRRset currentRrset = new SRRset();
        for (Iterator<Record> i = records.iterator(); i.hasNext();) {
            r = i.next();

            // Skip RR types that cannot be used as trust anchors.
            if (r.getType() != Type.DNSKEY && r.getType() != Type.DS) {
                continue;
            }

            // If our current set is empty, we can just add it.
            if (currentRrset.size() == 0) {
                currentRrset.addRR(r);
                continue;
            }

            // If this record matches our current RRset, we can just add it.
            if (currentRrset.getName().equals(r.getName()) && currentRrset.getType() == r.getType() && currentRrset.getDClass() == r.getDClass()) {
                currentRrset.addRR(r);
                continue;
            }

            // Otherwise, we add the rrset to our set of trust anchors and begin
            // a new set
            this.trustAnchors.store(currentRrset);
            currentRrset = new SRRset();
            currentRrset.addRR(r);
        }

        // add the last rrset (if it was not empty)
        if (currentRrset.size() > 0) {
            this.trustAnchors.store(currentRrset);
        }
    }

    /**
     * Gets the store with the loaded trust anchors.
     * 
     * @return The store with the loaded trust anchors.
     */
    public TrustAnchorStore getTrustAnchors() {
        return this.trustAnchors;
    }

    // ---------------- Request/ResponseType Preparation ------------
    /**
     * Given a request, decorate the request to fetch DNSSEC information.
     * 
     * @param req The request.
     */
    private void prepareRequest(Message req) {
        // First we make sure that the request:
        // A) has the DNSSEC OK (DO) bit turned on.
        // B) has the Checking Disabled (CD) bit turned on. This is to prevent
        // some upstream DNS software from validating for us.

        req.getHeader().setFlag(Flags.CD);
    }

    // ----------------- Resolution Support -----------------------

    /**
     * Generate a request for a "local" event. That is, generate a request that
     * is logically owned by this module.
     * 
     * @param qname The query name.
     * @param qtype The query type.
     * @param qclass The query class.
     * 
     * @return A request.
     */
    private Message generateLocalRequest(Name qname, int qtype, int qclass) {
        Record r = Record.newRecord(qname, qtype, qclass);
        Message m = Message.newQuery(r);
        m.getHeader().setFlag(Flags.RD);
        return m;
    }

    /**
     * Generate a local event. Local events are tied to this module, and have a
     * corresponding (first tier) event that is waiting for this event to
     * resolve to continue.
     * 
     * @param forEvent The event that is generating this event.
     * @param req The request for this event.
     * @param initialState The initial state for this event. This controls where
     *            the response to this event initially goes.
     * @param finalState The final state for this event. This controls where the
     *            response to this event goes after finishing validation.
     * @return The generated event.
     */
    private DNSEvent generateLocalEvent(DNSEvent forEvent, Message req) {
        DNSEvent event = new DNSEvent(req, forEvent);
        ValEventState state = new ValEventState();
        event.setModuleState(state);

        return event;
    }

    /**
     * Given a "postive" response -- a response that contains an answer to the
     * question, and no CNAME chain, validate this response. This generally
     * consists of verifying the answer RRset and the authority RRsets.
     * 
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     * 
     * @param response The response to validate.
     * @param request The request that generated this response.
     * @param keyRrset The trusted DNSKEY rrset that matches the signer of the
     *            answer.
     */
    private void validatePositiveResponse(SMessage response, Message request) {
        Name qname = request.getQuestion().getName();
        int qtype = request.getQuestion().getType();

        // validate the ANSWER section - this will be the answer itself
        Name wc = null;
        boolean wcNsecOk = false;
        DNAMERecord dname = null;
        List<NSEC3Record> nsec3s = null;

        SRRset keyRrset = null;
        for (SRRset set : response.getSectionRRsets(Section.ANSWER)) {
            // Validate the CNAME following a (validated) DNAME is correctly
            // synthesized.
            if (set.getType() == Type.CNAME && dname != null) {
                if (set.size() > 1) {
                    logger.debug("Synthesized CNAME RRset has multiple records - that doesn't make sense.");
                    response.setStatus(SecurityStatus.BOGUS);
                    return;
                }

                CNAMERecord cname = (CNAMERecord)set.first();
                try {
                    if (!Name.concatenate(cname.getName().relativize(dname.getName()), dname.getTarget()).equals(cname.getTarget())) {
                        logger.debug("Synthesized CNAME included in answer doesn't match DNAME synthesis rules, thus bogus.");
                        response.setStatus(SecurityStatus.BOGUS);
                        return;
                    }
                }
                catch (NameTooLongException e) {
                    logger.debug("Synthesized name would be too long, thus bogus");
                    response.setStatus(SecurityStatus.BOGUS);
                    return;
                }

                set.setSecurityStatus(SecurityStatus.SECURE);
                dname = null;
                continue;
            }

            // Verify the answer rrset.
            KeyEntry ke = this.prepareFindKey(set, qname);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            keyRrset = ke.getRRset();
            if (keyRrset == null) {
                logger.debug("Postive response has failed ANSWER rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                logger.debug("Postive response has failed ANSWER rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // Check to see if the rrset is the result of a wildcard expansion.
            // If so, an additional check will need to be made in the authority
            // section.
            wc = ValUtils.rrsetWildcard(set);

            // Notice a DNAME that should be followed by an unsigned CNAME.
            if (qtype != Type.DNAME && set.getType() == Type.DNAME) {
                dname = (DNAMERecord)set.first();
            }
        }

        // validate the AUTHORITY section as well - this will generally be the
        // NS rrset (which could be missing, no problem)
        for (SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, qname);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            keyRrset = ke.getRRset();
            if (keyRrset == null) {
                logger.debug("Postive response has failed AUTHORITY rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            // If anything in the authority section fails to be secure, we have
            // a bad message.
            if (status != SecurityStatus.SECURE) {
                logger.debug("Postive response has failed AUTHORITY rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // If this is a positive wildcard response, and we have a (just
            // verified) NSEC record, try to use it to
            // 1) prove that qname doesn't exist and
            // 2) that the correct wildcard was used.
            if (wc != null && set.getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord)set.first();

                if (ValUtils.nsecProvesNameError(nsec, qname, keyRrset.getName())) {
                    try {
                        Name nsecWc = ValUtils.nsecWildcard(qname, nsec);
                        if (!wc.equals(nsecWc)) {
                            logger.debug("Postive wildcard response wasn't generated by the correct wildcard");
                            response.setStatus(SecurityStatus.BOGUS);
                            return;
                        }
                    }
                    catch (NameTooLongException e) {
                        logger.debug("Could not generate NSEC wildcard", e);
                        response.setStatus(SecurityStatus.BOGUS);
                        return;
                    }

                    wcNsecOk = true;
                }
            }

            // Otherwise, if this is a positive wildcard response and we have
            // NSEC3 records, collect them.
            if (wc != null && set.getType() == Type.NSEC3) {
                if (nsec3s == null) {
                    nsec3s = new ArrayList<NSEC3Record>();
                }

                nsec3s.add((NSEC3Record)set.first());
            }
        }

        // If this was a positive wildcard response that we haven't already
        // proven, and we have NSEC3 records, try to prove it using the NSEC3
        // records.
        if (wc != null && !wcNsecOk && nsec3s != null) {
            if (NSEC3ValUtils.proveWildcard(nsec3s, qname, keyRrset.getName(), wc)) {
                wcNsecOk = true;
            }
        }

        // If after all this, we still haven't proven the positive wildcard
        // response, fail.
        if (wc != null && !wcNsecOk) {
            logger.debug("positive response was wildcard expansion and did not prove original data did not exist");
            response.setStatus(SecurityStatus.BOGUS);
            return;
        }

        logger.trace("Successfully validated postive response");
        response.setStatus(SecurityStatus.SECURE);
    }

    /**
     * Given an "ANY" response -- a response that contains an answer to a
     * qtype==ANY question, with answers. This consists of simply verifying all
     * present answer/auth RRsets, with no checking that all types are present.
     * 
     * NOTE: it may be possible to get parent-side delegation point records
     * here, which won't all be signed. Right now, this routine relies on the
     * upstream iterative resolver to not return these responses -- instead
     * treating them as referrals.
     * 
     * NOTE: RFC 4035 is silent on this issue, so this may change upon
     * clarification.
     * 
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     * 
     * @param response The response to validate.
     * @param request The request that generated this response.
     * @param keyRrset The trusted DNSKEY rrset that matches the signer of the
     *            answer.
     */
    private void validateAnyResponse(SMessage response, Message request) {
        Name qname = request.getQuestion().getName();
        int qtype = request.getQuestion().getType();

        if (qtype != Type.ANY) {
            throw new IllegalArgumentException("ANY validation called on non-ANY response.");
        }

        SMessage m = response;

        // validate the ANSWER section.
        for (SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, qname);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            SRRset keyRrset = ke.getRRset();
            if (keyRrset == null) {
                logger.debug("Postive response has failed ANSWER rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                logger.debug("Postive response has failed ANSWER rrset: " + set);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

        // validate the AUTHORITY section as well - this will be the NS rrset
        // (which could be missing, no problem)
        for (SRRset set : m.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, qname);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            SRRset keyRrset = ke.getRRset();
            if (keyRrset == null) {
                logger.debug("Postive response has failed ANSWER rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            // If anything in the authority section fails to be secure, we have
            // a bad message.
            if (status != SecurityStatus.SECURE) {
                logger.debug("Postive response has failed AUTHORITY rrset: " + set);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

        logger.trace("Successfully validated postive ANY response");
        m.setStatus(SecurityStatus.SECURE);
    }

    /**
     * Validate a NOERROR/NODATA signed response -- a response that has a
     * NOERROR Rcode but no ANSWER section RRsets. This consists of verifying
     * the authority section rrsets and making certain that the authority
     * section NSEC/NSEC3s proves that the qname does exist and the qtype
     * doesn't.
     * 
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     * 
     * @param response The response to validate.
     * @param request The request that generated this response.
     * @param keyRrset The trusted DNSKEY rrset that signs this response.
     */
    private void validateNodataResponse(SMessage response, Message request) {
        Name qname = request.getQuestion().getName();
        int qtype = request.getQuestion().getType();

        SMessage m = response;

        // Since we are here, the ANSWER section is either empty (and hence
        // there's only the NODATA to validate) OR it contains an incomplete
        // chain. In this case, the records were already validated before and we
        // can concentrate on following the qname that lead to the NODATA
        // classification
        for (SRRset set : m.getSectionRRsets(Section.ANSWER)) {
            if (set.getSecurityStatus() != SecurityStatus.SECURE) {
                logger.debug("CNAME_NODATA response has failed ANSWER rrset: " + set);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            if (set.getType() == Type.CNAME) {
                qname = ((CNAMERecord)set.first()).getTarget();
            }
        }

        // validate the AUTHORITY section
        boolean hasValidNSEC = false; // If true, then the NODATA has been
                                      // proven.
        Name ce = null; // for wildcard nodata responses. This is the proven
                        // closest encloser.
        NSECRecord wc = null; // for wildcard nodata responses. This is the
                              // wildcard NSEC.
        List<NSEC3Record> nsec3s = null; // A collection of NSEC3 RRs found in
                                         // the authority section.
        Name nsec3Signer = null; // The RRSIG signer field for the NSEC3 RRs.

        for (SRRset set : m.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, qname);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            SRRset keyRrset = ke.getRRset();
            if (keyRrset == null) {
                logger.debug("NODATA response has failed AUTHORITY rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            if (status != SecurityStatus.SECURE) {
                logger.debug("NODATA response has failed AUTHORITY rrset: " + set);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // If we encounter an NSEC record, try to use it to prove NODATA.
            // This needs to handle the empty non-terminal (ENT) NODATA case.
            if (set.getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord)set.first();
                if (ValUtils.nsecProvesNodata(nsec, qname, qtype)) {
                    hasValidNSEC = true;
                    if (nsec.getName().isWild()) {
                        wc = nsec;
                    }
                }
                else if (ValUtils.nsecProvesNameError(nsec, qname, set.getSignerName())) {
                    ce = ValUtils.closestEncloser(qname, nsec);
                }
            }

            // Collect any NSEC3 records present.
            if (set.getType() == Type.NSEC3) {
                if (nsec3s == null) {
                    nsec3s = new ArrayList<NSEC3Record>();
                }

                nsec3s.add((NSEC3Record)set.first());
                nsec3Signer = set.getSignerName();
            }
        }

        // check to see if we have a wildcard NODATA proof.

        // The wildcard NODATA is 1 NSEC proving that qname does not exists (and
        // also proving what the closest encloser is), and 1 NSEC showing the
        // matching wildcard, which must be *.closest_encloser.
        if (ce != null || wc != null) {
            try {
                Name wcName = new Name("*", ce);
                if (!wcName.equals(wc.getName())) {
                    hasValidNSEC = false;
                }
            }
            catch (TextParseException e) {
                logger.error(e);
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);
        if (!hasValidNSEC && nsec3s != null && nsec3s.size() > 0) {
            // try to prove NODATA with our NSEC3 record(s)
            hasValidNSEC = NSEC3ValUtils.proveNodata(nsec3s, qname, qtype, nsec3Signer);
        }

        if (!hasValidNSEC) {
            logger.debug("NODATA response failed to prove NODATA " + "status with NSEC/NSEC3");
            logger.trace("Failed NODATA:\n" + m);
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        logger.trace("sucessfully validated NODATA response.");
        m.setStatus(SecurityStatus.SECURE);
    }

    /**
     * Validate a NAMEERROR signed response -- a response that has a NXDOMAIN
     * Rcode. This consists of verifying the authority section rrsets and making
     * certain that the authority section NSEC proves that the qname doesn't
     * exist and the covering wildcard also doesn't exist..
     * 
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     * 
     * @param qname The name to be proved to not exist.
     * @param response The response to validate.
     * @param keyRrset The trusted DNSKEY rrset that signs this response.
     */
    private void validateNameErrorResponse(Name qname, SMessage response) {
        // The ANSWER section is either empty OR it contains an xNAME chain that
        // ultimately lead to the NAMEERROR response. In this case the ANSWER
        // section has already been validated before and we can concentrate on
        // following the xNAMEs to find the qname that caused the NXDOMAIN.
        for (SRRset set : response.getSectionRRsets(Section.ANSWER)) {
            if (set.getSecurityStatus() != SecurityStatus.SECURE) {
                logger.debug("CNAME_NAMEERROR response has failed ANSWER rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            if (set.getType() == Type.CNAME) {
                qname = ((CNAMERecord)set.first()).getTarget();
            }
        }

        // Validate the authority section -- all RRsets in the authority section
        // must be signed and valid.
        // In addition, the NSEC record(s) must prove the NXDOMAIN condition.
        boolean hasValidNSEC = false;
        boolean hasValidWCNSEC = false;
        List<NSEC3Record> nsec3s = null;
        Name nsec3Signer = null;
        SRRset keyRrset = null;

        for (SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, qname);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            keyRrset = ke.getRRset();
            if (keyRrset == null) {
                logger.debug("NameError response has failed AUTHORITY rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            if (status != SecurityStatus.SECURE) {
                logger.debug("NameError response has failed AUTHORITY rrset: " + set);
                response.setStatus(SecurityStatus.BOGUS);
                return;
            }

            if (set.getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord)set.first();
                if (ValUtils.nsecProvesNameError(nsec, qname, set.getSignerName())) {
                    hasValidNSEC = true;
                }

                if (ValUtils.nsecProvesNoWC(nsec, qname, set.getSignerName())) {
                    hasValidWCNSEC = true;
                }
            }

            if (set.getType() == Type.NSEC3) {
                if (nsec3s == null) {
                    nsec3s = new ArrayList<NSEC3Record>();
                }

                nsec3s.add((NSEC3Record)set.first());
                nsec3Signer = set.getSignerName();
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);
        if (nsec3s != null && nsec3s.size() > 0) {
            logger.debug("Validating nxdomain: using NSEC3 records");
            // Attempt to prove name error with nsec3 records.

            if (NSEC3ValUtils.allNSEC3sIgnoreable(nsec3s, keyRrset)) {
                logger.debug("all NSEC3s were validated but ignored.");
                response.setStatus(SecurityStatus.INSECURE);
                return;
            }

            hasValidNSEC = NSEC3ValUtils.proveNameError(nsec3s, qname, nsec3Signer);

            // Note that we assume that the NSEC3ValUtils proofs encompass the
            // wildcard part of the proof.
            hasValidWCNSEC = hasValidNSEC;
        }

        // If the message fails to prove either condition, it is bogus.
        if (!hasValidNSEC) {
            logger.debug("NameError response has failed to prove that the qname does not exist");
            response.setStatus(SecurityStatus.BOGUS);
            return;
        }

        if (!hasValidWCNSEC) {
            logger.debug("NameError response has failed to prove that the covering wildcard does not exist");
            response.setStatus(SecurityStatus.BOGUS);
            return;
        }

        // Otherwise, we consider the message secure.
        logger.trace("successfully validated NAME ERROR response.");
        response.setStatus(SecurityStatus.SECURE);
    }

    // ----------------- Resolution Support -----------------------

    private void sendRequest(DNSEvent event) {
        Record q = event.getRequest().getQuestion();
        logger.trace("sending request: <" + q.getName() + "/" + Type.string(q.getType()) + "/" + DClass.string(q.getDClass()) + ">");

        // Add a module state object to every request.
        // Locally generated requests will already have state.
        ValEventState state = event.getModuleState();
        if (state == null) {
            state = new ValEventState();
            event.setModuleState(state);
        }

        // (Possibly) modify the request to add the CD bit.
        this.prepareRequest(event.getRequest());

        // Send the request along by using a local copy of the request
        Message localRequest = (Message)event.getRequest().clone();
        try {
            Message resp = this.headResolver.send(localRequest);
            event.setResponse(new SMessage(resp));
        }
        catch (SocketTimeoutException e) {
            logger.error("Query timed out, returning fail", e);
            event.setResponse(Util.errorMessage(localRequest, Rcode.SERVFAIL));
        }
        catch (UnknownHostException e) {
            logger.error("failed to send query", e);
            event.setResponse(Util.errorMessage(localRequest, Rcode.SERVFAIL));
        }
        catch (IOException e) {
            logger.error("failed to send query", e);
            event.setResponse(Util.errorMessage(localRequest, Rcode.SERVFAIL));
        }
    }

    private KeyEntry prepareFindKey(SRRset rrset, Name qname) {
        DNSEvent event = new DNSEvent(new Message());
        event.setModuleState(new ValEventState());
        ValEventState state = event.getModuleState();
        state.signerName = rrset.getSignerName();

        if (state.signerName == null) {
            state.signerName = qname;
        }

        state.trustAnchorRRset = this.trustAnchors.find(state.signerName, rrset.getDClass());
        if (state.trustAnchorRRset == null) {
            // response isn't under a trust anchor, so we cannot validate.
            return KeyEntry.newNullKeyEntry(rrset.getSignerName(), rrset.getDClass(), DEFAULT_TA_BAD_KEY_TTL);
            // return null;
        }

        state.keyEntry = this.keyCache.find(state.signerName, rrset.getDClass());
        if (state.keyEntry == null || (!state.keyEntry.getName().equals(state.signerName) && state.keyEntry.isGood())) {
            // start the FINDKEY phase with the trust anchor
            if (state.trustAnchorRRset.getType() == Type.DS) {
                state.dsRRset = state.trustAnchorRRset;
            }
            else if (state.keyEntry == null) {
                state.keyEntry = KeyEntry.newKeyEntry(state.trustAnchorRRset);
            }

            // and otherwise, don't continue processing this event.
            // (it will be reactivated when the priming query returns).
            processFindKey(event, state);
        }

        return state.keyEntry;
    }

    /**
     * Process the FINDKEY state. Generally this just calculates the next name
     * to query and either issues a DS or a DNSKEY query. It will check to see
     * if the correct key has already been reached, in which case it will
     * advance the event to the next state.
     * 
     * @param event The first tier event.
     * @param state The state for that event.
     * @return true if this event should continue to be processed, false if not.
     */
    private boolean processFindKey(DNSEvent event, ValEventState state) {
        // We know that state.keyEntry is not a null or bad key -- if it were,
        // then previous processing should have directed this event to a
        // different state.
        // Message req = event.getRequest();
        // Name qname = req.getQuestion().getName();
        int qclass = DClass.IN; // req.getQuestion().getDClass();

        Name targetKeyName = state.signerName;
        // if (targetKeyName == null) {
        // targetKeyName = qname;
        // }

        Name currentKeyName = Name.empty;
        if (state.keyEntry != null) {
            currentKeyName = state.keyEntry.getName();
        }

        // If our current key entry matches our target, then we are done.
        if (currentKeyName.equals(targetKeyName)) {
            return true;
        }

        if (state.emptyDSName != null) {
            currentKeyName = state.emptyDSName;
        }

        // Calculate the next lookup name.
        int targetLabels = targetKeyName.labels();
        int currentLabels = currentKeyName.labels();
        int l = targetLabels - currentLabels - 1;

        // the next key name would be trying to invent a name, so we stop here
        if (l < 0) {
            return true;
        }

        Name nextKeyName = new Name(targetKeyName, l);
        logger.trace("findKey: targetKeyName = " + targetKeyName + ", currentKeyName = " + currentKeyName + ", nextKeyName = " + nextKeyName);
        // The next step is either to query for the next DS, or to query for the
        // next DNSKEY.

        if (state.dsRRset == null || !state.dsRRset.getName().equals(nextKeyName)) {
            Message dsRequest = this.generateLocalRequest(nextKeyName, Type.DS, qclass);
            DNSEvent dsEvent = this.generateLocalEvent(event, dsRequest);
            this.sendRequest(dsEvent);
            this.processDSResponse(dsEvent, dsEvent.getModuleState());
            return false;
        }

        // Otherwise, it is time to query for the DNSKEY
        Message dnskeyRequest = this.generateLocalRequest(state.dsRRset.getName(), Type.DNSKEY, qclass);
        DNSEvent dnskeyEvent = this.generateLocalEvent(event, dnskeyRequest);
        this.sendRequest(dnskeyEvent);
        this.processDNSKEYResponse(dnskeyEvent, dnskeyEvent.getModuleState());

        return false;
    }

    /**
     * Given a DS response, the DS request, and the current key rrset, validate
     * the DS response, returning a KeyEntry.
     * 
     * @param response The DS response.
     * @param request The DS request.
     * @param keyRrset The current DNSKEY rrset from the forEvent state.
     * 
     * @return A KeyEntry, bad if the DS response fails to validate, null if the
     *         DS response indicated an end to secure space, good if the DS
     *         validated. It returns null if the DS response indicated that the
     *         request wasn't a delegation point.
     */
    private KeyEntry dsResponseToKE(SMessage response, Message request, SRRset keyRrset) {
        Name qname = request.getQuestion().getName();
        int qclass = request.getQuestion().getDClass();

        SecurityStatus status;
        ResponseClassification subtype = ValUtils.classifyResponse(response);

        KeyEntry bogusKE = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
        switch (subtype) {
            case POSITIVE:
                // Verify only returns BOGUS or SECURE. If the rrset is bogus,
                // then we are done.
                SRRset dsRrset = response.findAnswerRRset(qname, Type.DS, qclass);
                status = this.valUtils.verifySRRset(dsRrset, keyRrset);
                if (status != SecurityStatus.SECURE) {
                    logger.debug("DS rrset in DS response did not verify");
                    return bogusKE;
                }

                // Otherwise, we return the positive response.
                logger.trace("DS rrset was good.");
                return KeyEntry.newKeyEntry(dsRrset);

            case CNAME:
                // Verify only returns BOGUS or SECURE. If the rrset is bogus,
                // then we are done.
                SRRset cnameRrset = response.findAnswerRRset(qname, Type.CNAME, qclass);
                status = this.valUtils.verifySRRset(cnameRrset, keyRrset);
                if (status != SecurityStatus.SECURE) {
                    logger.debug("CNAME rrset in DS response did not verify");
                    return bogusKE;
                }

                // Otherwise, we return the positive response.
                logger.trace("CNAME rrset was good, unsigned response.");
                return KeyEntry.newNullKeyEntry(cnameRrset.getName(), qclass, DEFAULT_TA_BAD_KEY_TTL);

            case NODATA:
                // NODATA means that the qname exists, but that there was no DS.
                // This is a pretty normal case.
                SRRset nsecRrset = response.findRRset(qname, Type.NSEC, qclass, Section.AUTHORITY);

                // If we have a NSEC at the same name, it must prove one of two
                // things
                // --
                // 1) this is a delegation point and there is no DS
                // 2) this is not a delegation point
                if (nsecRrset != null) {
                    // The NSEC must verify, first of all.
                    status = this.valUtils.verifySRRset(nsecRrset, keyRrset);
                    if (status != SecurityStatus.SECURE) {
                        logger.debug("NSEC RRset for the referral did not verify.");
                        return bogusKE;
                    }

                    NSECRecord nsec = (NSECRecord)nsecRrset.first();
                    switch (ValUtils.nsecProvesNoDS(nsec, qname)) {
                        case BOGUS: // something was wrong.
                            logger.debug("NSEC RRset for the referral did not prove no DS.");
                            return bogusKE;
                        case INSECURE: // this wasn't a delegation point.
                            logger.debug("NSEC RRset for the referral proved not a delegation point");
                            return null;
                        case SECURE: // this proved no DS.
                            logger.debug("NSEC RRset for the referral proved no DS.");
                            return KeyEntry.newNullKeyEntry(qname, qclass, nsecRrset.getTTL());
                        default:
                            throw new RuntimeException("unexpected security status");
                    }
                }

                // Otherwise, there is no NSEC at qname. This could be an ENT.
                // If not, this is broken.
                for (SRRset set : response.getSectionRRsets(Section.AUTHORITY, Type.NSEC)) {
                    status = this.valUtils.verifySRRset(set, keyRrset);
                    if (status != SecurityStatus.SECURE) {
                        logger.debug("NSEC for empty non-terminal did not verify.");
                        return bogusKE;
                    }
                    NSECRecord nsec = (NSECRecord)set.first();
                    if (ValUtils.nsecProvesNodata(nsec, qname, Type.DS)) {
                        logger.debug("NSEC for empty non-terminal proved no DS.");
                        return KeyEntry.newNullKeyEntry(qname, qclass, set.getTTL());
                    }
                }

                // Or it could be using NSEC3.
                SRRset[] nsec3Rrsets = response.getSectionRRsets(Section.AUTHORITY, Type.NSEC3);
                List<NSEC3Record> nsec3s = new ArrayList<NSEC3Record>();
                Name nsec3Signer = null;
                long nsec3TTL = -1;
                if (nsec3Rrsets != null && nsec3Rrsets.length > 0) {
                    // Attempt to prove no DS with NSEC3s.
                    for (SRRset nsec3set : nsec3Rrsets) {
                        status = this.valUtils.verifySRRset(nsec3set, keyRrset);
                        if (status != SecurityStatus.SECURE) {
                            // FIXME: we could just fail here -- there is an
                            // invalid rrset -- but is more robust to skip like
                            // we are.
                            logger.debug("skipping bad nsec3");
                            continue;
                        }

                        NSEC3Record nsec3 = (NSEC3Record)nsec3set.first();
                        nsec3Signer = nsec3set.getSignerName();
                        if (nsec3TTL < 0 || nsec3set.getTTL() < nsec3TTL) {
                            nsec3TTL = nsec3set.getTTL();
                        }

                        nsec3s.add(nsec3);
                    }

                    switch (NSEC3ValUtils.proveNoDS(nsec3s, qname, nsec3Signer)) {
                        case BOGUS:
                            logger.debug("nsec3s proved bogus.");
                            return bogusKE;
                        case INSECURE:
                            logger.debug("nsec3s proved no delegation.");
                            return null;
                        case SECURE:
                            logger.debug("nsec3 proved no ds.");
                            return KeyEntry.newNullKeyEntry(qname, qclass, nsec3TTL);
                        default:
                            throw new RuntimeException("unexpected security status");
                    }
                }

                // Apparently, no available NSEC/NSEC3 proved NODATA, so this is
                // BOGUS.
                logger.debug("ran out of options, so return bogus");
                return bogusKE;

            case NAMEERROR:
                // NAMEERRORs at this point pretty much break validation
                logger.debug("DS response was NAMEERROR, thus bogus.");
                return bogusKE;
            default:
                // We've encountered an unhandled classification for this
                // response.
                logger.debug("Encountered an unhandled type of DS response, thus bogus (" + subtype + ").");
                return bogusKE;
        }
    }

    /**
     * This handles the responses to locally generated DS queries.
     * 
     * @param event The DS query response event.
     * @param state The state associated with the DS response event.
     * @return false, as generally there is never any additional processing for
     *         these events.
     */
    private boolean processDSResponse(DNSEvent event, ValEventState state) {
        Message dsRequest = event.getRequest();
        SMessage dsResp = event.getResponse();

        Name qname = dsRequest.getQuestion().getName();

        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        forState.emptyDSName = null;
        forState.dsRRset = null;

        KeyEntry dsKE = this.dsResponseToKE(dsResp, dsRequest, forState.keyEntry.getRRset());

        if (dsKE == null) {
            forState.emptyDSName = qname;
            // ds response indicated that we aren't on a delegation point.
            // Keep the forState.state on FINDKEY.
        }
        else if (dsKE.isGood()) {
            forState.dsRRset = dsKE.getRRset();
            // Keep the forState.state on FINDKEY.
        }
        else {
            // NOTE: the reason for the DS to be not good (that is, either bad
            // or null) should have been logged by dsResponseToKE.
            forState.keyEntry = dsKE;
            if (dsKE.isNull()) {
                this.keyCache.store(dsKE);
            }

            // The FINDKEY phase has ended, so move on.
            return false;
        }

        // this.processResponse(forEvent);
        this.processFindKey(forEvent, forState);
        return false;
    }

    private boolean processDNSKEYResponse(DNSEvent event, ValEventState state) {
        Message dnskeyRequest = event.getRequest();
        SMessage dnskeyResp = event.getResponse();
        Name qname = dnskeyRequest.getQuestion().getName();
        int qclass = dnskeyRequest.getQuestion().getDClass();

        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        SRRset dsRrset = forState.dsRRset;
        SRRset dnskeyRrset = dnskeyResp.findAnswerRRset(qname, Type.DNSKEY, qclass);

        if (dnskeyRrset == null) {
            // If the DNSKEY rrset was missing, this is the end of the line.
            logger.debug("Missing DNSKEY RRset in response to DNSKEY query.");
            forState.keyEntry = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);

            return false;
        }

        forState.keyEntry = this.valUtils.verifyNewDNSKEYs(dnskeyRrset, dsRrset, DEFAULT_TA_BAD_KEY_TTL);

        // If the key entry isBad or isNull, then we can move on to the next
        // state.
        if (!forState.keyEntry.isGood()) {
            if (logger.isDebugEnabled() && forState.keyEntry.isBad()) {
                logger.debug("Did not match a DS to a DNSKEY, thus bogus.");
            }

            return false;
        }

        // The DNSKEY validated, so cache it as a trusted key rrset.
        this.keyCache.store(forState.keyEntry);

        // If good, we stay in the FINDKEY state.
        // this.processResponse(forEvent);
        this.processFindKey(forEvent, forState);
        return false;
    }

    private boolean processKeyValidate(SMessage resp, Name signerName, KeyEntry keyEntry) {
        // signerName being null is the indicator that this response was
        // unsigned
        if (signerName == null) {
            logger.debug("processKeyValidate: no signerName.");
            // Unsigned responses must be underneath a "null" key entry.
            if (keyEntry.isNull()) {
                logger.debug("Unsigned response was proved to be validly INSECURE");
                resp.setStatus(SecurityStatus.INSECURE);
                return false;
            }

            logger.debug("Could not establish validation of " + "INSECURE status of unsigned response.");
            resp.setStatus(SecurityStatus.BOGUS);
            return false;
        }

        if (keyEntry.isBad()) {
            logger.debug("Could not establish a chain of trust to keys for: " + keyEntry.getName());
            resp.setStatus(SecurityStatus.BOGUS);
            return false;
        }

        if (keyEntry.isNull()) {
            logger.debug("Verified that response is INSECURE");
            resp.setStatus(SecurityStatus.INSECURE);
            return false;
        }

        return true;
    }

    private boolean processValidate(DNSEvent event, ValEventState state) {
        Message req = event.getRequest();
        SMessage resp = event.getResponse();

        ResponseClassification subtype = ValUtils.classifyResponse(resp);

        switch (subtype) {
            case POSITIVE:
                logger.trace("Validating a positive response");
                this.validatePositiveResponse(resp, req);
                break;
            case NODATA:
                logger.trace("Validating a nodata response");
                this.validateNodataResponse(resp, req);
                break;
            case CNAME_NODATA:
                logger.trace("Validating a CNAME_NODATA response");
                this.validatePositiveResponse(resp, req);
                if (resp.getStatus() != SecurityStatus.INSECURE) {
                    resp.setStatus(SecurityStatus.UNCHECKED);
                    this.validateNodataResponse(resp, req);
                }
                break;
            case NAMEERROR:
                logger.trace("Validating a nxdomain response");
                this.validateNameErrorResponse(req.getQuestion().getName(), resp);
                break;
            case CNAME_NAMEERROR:
                logger.trace("Validating a cname_nxdomain response");
                this.validatePositiveResponse(resp, req);
                if (resp.getStatus() != SecurityStatus.INSECURE) {
                    resp.setStatus(SecurityStatus.UNCHECKED);
                    this.validateNameErrorResponse(req.getQuestion().getName(), resp);
                }
                break;
            case ANY:
                logger.trace("Validating a postive ANY response");
                this.validateAnyResponse(resp, req);
                break;
            default:
                logger.error("unhandled response subtype: " + subtype);
        }

        this.processFinishedState(event, state);
        return true;
    }

    /**
     * Apply any final massaging to a response before returning up the pipeline.
     * Primarily this means setting the AD bit or not and possibly stripping
     * DNSSEC data.
     */
    private boolean processFinishedState(DNSEvent event, ValEventState state) {
        SMessage resp = event.getResponse();
        Message origRequest = event.getOrigRequest();

        // If the CD bit is set, do not process the (cached) validation status.
        if (!origRequest.getHeader().getFlag(Flags.CD)) {
            // If the response message validated, set the AD bit.
            SecurityStatus status = resp.getStatus();
            switch (status) {
                case BOGUS:
                    // For now, in the absence of any other API information, we
                    // return SERVFAIL.
                    int code = resp.getHeader().getRcode();
                    if (code == Rcode.NOERROR || code == Rcode.NXDOMAIN) {
                        code = Rcode.SERVFAIL;
                    }

                    resp = Util.errorMessage(origRequest, code);
                    event.setResponse(resp);
                    break;
                case SECURE:
                    resp.getHeader().setFlag(Flags.AD);
                    break;
                case UNCHECKED:
                case INSECURE:
                    break;
                default:
                    throw new RuntimeException("unexpected security status");
            }
        }

        return false;
    }

    // Resolver-interface implementation --------------------------------------
    /**
     * Forwards the data to the head resolver passed at construction time.
     * 
     * @param port The IP destination port for the queries sent.
     * @see org.xbill.DNS.Resolver#setPort(int)
     */
    public void setPort(int port) {
        this.headResolver.setPort(port);
    }

    /**
     * Forwards the data to the head resolver passed at construction time.
     * 
     * @param flag <code>true</code> to enable TCP, <code>false</code> to
     *            disable it.
     * @see org.xbill.DNS.Resolver#setTCP(boolean)
     */
    public void setTCP(boolean flag) {
        this.headResolver.setTCP(flag);
    }

    /**
     * This is a no-op, truncation is never ignored.
     * 
     * @param flag unused
     */
    public void setIgnoreTruncation(boolean flag) {
    }

    /**
     * This is a no-op, EDNS is always set to level 0.
     * 
     * @param level unused
     */
    public void setEDNS(int level) {
    }

    /**
     * The method is forwarded to the resolver, but always ensure that the level
     * is 0 and the flags contains DO.
     * 
     * @param level unused, always set to 0.
     * @param payloadSize The maximum DNS packet size that this host is capable
     *            of receiving over UDP. If 0 is specified, the default (1280)
     *            is used.
     * @param flags EDNS extended flags to be set in the OPT record,
     *            {@link ExtendedFlags#DO} is always appended.
     * @param options EDNS options to be set in the OPT record, specified as a
     *            List of OPTRecord.Option elements.
     * @see org.xbill.DNS.Resolver#setEDNS(int, int, int, java.util.List)
     */
    public void setEDNS(int level, int payloadSize, int flags, @SuppressWarnings("rawtypes") List options) {
        this.headResolver.setEDNS(0, payloadSize, flags | ExtendedFlags.DO, options);
    }

    /**
     * Forwards the data to the head resolver passed at construction time.
     * 
     * @param key The key.
     * @see org.xbill.DNS.Resolver#setTSIGKey(org.xbill.DNS.TSIG)
     */
    public void setTSIGKey(TSIG key) {
        this.headResolver.setTSIGKey(key);
    }

    /**
     * Sets the amount of time to wait for a response before giving up. This
     * applies only to the head resolver, the time for an actual query to the
     * validating resolver IS higher.
     * 
     * @param secs The number of seconds to wait.
     * @param msecs The number of milliseconds to wait.
     */
    public void setTimeout(int secs, int msecs) {
        this.headResolver.setTimeout(secs, msecs);
    }

    /**
     * Sets the amount of time to wait for a response before giving up. This
     * applies only to the head resolver, the time for an actual query to the
     * validating resolver IS higher.
     * 
     * @param secs The number of seconds to wait.
     */
    public void setTimeout(int secs) {
        this.headResolver.setTimeout(secs);
    }

    /**
     * Sends a message and validates the response with DNSSEC before returning
     * it.
     * 
     * @param query The query to send.
     * @return The validated response message.
     * @throws IOException An error occurred while sending or receiving.
     */
    public Message send(Message query) throws IOException {
        DNSEvent event = new DNSEvent(query);

        // This should synchronously process the request, based on the way the
        // resolver tail is configured.
        this.sendRequest(event);
        // this.processInit(event, event.getModuleState());
        this.processValidate(event, event.getModuleState());

        return event.getResponse().getMessage();
    }

    /**
     * Not implemented.
     * 
     * @param query The query to send
     * @param listener The object containing the callbacks.
     * @return An identifier, which is also a parameter in the callback
     * @throws UnsupportedOperationException
     */
    public Object sendAsync(Message query, ResolverListener listener) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
