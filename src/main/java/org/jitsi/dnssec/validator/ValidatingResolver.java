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
import java.util.*;

import org.apache.log4j.Logger;
import org.jitsi.dnssec.DNSEvent;
import org.jitsi.dnssec.SMessage;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.jitsi.dnssec.Util;
import org.xbill.DNS.*;

/**
 * This resolver module implements the "validator" logic.
 * 
 * 
 * @author davidb
 * @version $Revision: 361 $
 */
public class ValidatingResolver implements Resolver {
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

    private Logger log = Logger.getLogger(this.getClass());

    // This is the TTL to use when a trust anchor fails to prime. A trust anchor
    // will be primed no more often than this interval.
    private static final long DEFAULT_TA_NULL_KEY_TTL = 60;

    private Resolver headResolver;

    public ValidatingResolver(Resolver headResolver) throws UnknownHostException {
        this.headResolver = headResolver;
        headResolver.setEDNS(0, 0, ExtendedFlags.DO, null);
        headResolver.setIgnoreTruncation(false);

        keyCache = new KeyCache();
        valUtils = new ValUtils(new DnsSecVerifier());
        trustAnchors = new TrustAnchorStore();
    }

    public TrustAnchorStore getTrustAnchors() {
        return this.trustAnchors;
    }

    // ---------------- Module Initialization -------------------

    /**
     * Initialize the module.
     */
    public void init(Properties config) throws Exception {
        keyCache.init(config);

        // Load trust anchors
        String s = config.getProperty("org.jitsi.dnssec.trust_anchor_file");
        if (s != null) {
            try {
                log.debug("reading trust anchor file file: " + s);
                loadTrustAnchors(new FileInputStream(s));
            }
            catch (IOException e) {
                log.error("Problems loading trust anchors from file", e);
            }
        }
    }

    /**
     * Load the trust anchor file into the trust anchor store. The trust anchors
     * are currently stored in a zone file format list of DNSKEY or DS records.
     * 
     * @param filename The trust anchor file.
     * @throws IOException
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

        SRRset cur_rrset = new SRRset();
        for (Iterator<Record> i = records.iterator(); i.hasNext();) {
            r = i.next();
            // Skip RR types that cannot be used as trust anchors.
            if (r.getType() != Type.DNSKEY && r.getType() != Type.DS)
                continue;

            // If our cur_rrset is empty, we can just add it.
            if (cur_rrset.size() == 0) {
                cur_rrset.addRR(r);
                continue;
            }
            // If this record matches our current RRset, we can just add it.
            if (cur_rrset.getName().equals(r.getName()) && cur_rrset.getType() == r.getType() && cur_rrset.getDClass() == r.getDClass()) {
                cur_rrset.addRR(r);
                continue;
            }

            // Otherwise, we add the rrset to our set of trust anchors.
            trustAnchors.store(cur_rrset);
            cur_rrset = new SRRset();
            cur_rrset.addRR(r);
        }

        // add the last rrset (if it was not empty)
        if (cur_rrset.size() > 0) {
            trustAnchors.store(cur_rrset);
        }
    }

    // ---------------- Request/ResponseType Preparation ------------
    /**
     * Given a request, decorate the request to fetch DNSSEC information.
     * 
     * @param req The request.
     * @return The decorated request.
     */
    private void prepareRequest(Message req) {
        // First we make sure that the request:
        // A) has the DNSSEC OK (DO) bit turned on.
        // B) has the Checking Disabled (CD) bit turned on. This is to prevent
        // some upstream DNS software from validating for us.

        req.getHeader().setFlag(Flags.CD);
    }

    /**
     * Check to see if a given RRset answers a given question. This is primarily
     * used to distinguish between DNSSEC RRsets that must be stripped vs. those
     * that must be retained because they answer the question.
     * 
     * @param rname The rrset name.
     * @param rtype The rrset type.
     * @param qname The query name
     * @param qtype The query type
     * @param section The section the rrset was found in.
     * 
     * @return true if the rrset is an answer.
     */
    private boolean isAnswerRRset(Name rname, int rtype, Name qname, int qtype, int section) {
        if (section != Section.ANSWER)
            return false;
        if (qtype == rtype && qname.equals(rname))
            return true;
        return false;
    }

    /**
     * Apply any final massaging to a response before returning up the pipeline.
     * Primarily this means setting the AD bit or not and possibly stripping
     * DNSSEC data.
     * 
     * @param response The response to modify. The response should have a
     *            reference to the query that generated the response.
     * @return The massaged response.
     */
    private void normalizeResponse(DNSEvent event, ValEventState state) {
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
                    resp = Util.errorMessage(origRequest, Rcode.SERVFAIL);
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
    }

    // ----------------- Validation Support ----------------------

    /**
     * Check to see if a given response needs to go through the validation
     * process. Typical reasons for this routine to return false are: CD bit was
     * on in the original request, the response was already validated, or the
     * response is a kind of message that is unvalidatable (i.e., SERVFAIL,
     * REFUSED, etc.)
     * 
     * @param response The response to check.
     * @param origRequest The original request received from the client.
     * 
     * @return true if the response could use validation (although this does not
     *         mean we can actually validate this response).
     */
    private boolean needsValidation(SMessage response, Message origRequest) {
        // If the CD bit is on in the original request, then we don't bother to
        // validate anything.
        if (origRequest.getHeader().getFlag(Flags.CD)) {
            log.debug("not validating response due to CD bit");
            return false;
        }

        if (response.getStatus().getStatus() > SecurityStatus.BOGUS.getStatus()) {
            log.debug("response has already been validated");
            return false;
        }

        int rcode = response.getRcode();
        if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
            log.debug("cannot validate non-answer.");
            log.trace("non-answer: " + response);
            return false;
        }

        return true;
    }

    /**
     * Generate and dispatch a priming query for the given trust anchor.
     * 
     * @param forEvent Link this event to the priming query. As part of
     *            processing the priming query's response, this event will be
     *            revived.
     * @param trust_anchor_rrset The RRset to start with -- this can be either a
     *            DNSKEY or a DS rrset. The RRset does not need to be signed.
     */
    private void primeTrustAnchor(DNSEvent forEvent, SRRset trust_anchor_rrset) {
        Name qname = trust_anchor_rrset.getName();
        int qtype = trust_anchor_rrset.getType();
        int qclass = trust_anchor_rrset.getDClass();

        log.debug("Priming Trust Anchor: " + qname + "/" + Type.string(qtype) + "/" + DClass.string(qclass));

        Message req = generateLocalRequest(qname, Type.DNSKEY, qclass);
        DNSEvent priming_query_event = generateLocalEvent(forEvent, req, ValEventState.PRIME_RESP_STATE, ValEventState.PRIME_RESP_STATE);

        processRequest(priming_query_event);
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
     * @param initial_state The initial state for this event. This controls
     *            where the response to this event initially goes.
     * @param final_state The final state for this event. This controls where
     *            the response to this event goes after finishing validation.
     * @return The generated event.
     */
    private DNSEvent generateLocalEvent(DNSEvent forEvent, Message req, int initial_state, int final_state) {
        DNSEvent event = new DNSEvent(req, forEvent);
        ValEventState state = new ValEventState();
        state.state = initial_state;
        state.finalState = final_state;

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
     * @param key_rrset The trusted DNSKEY rrset that matches the signer of the
     *            answer.
     */
    private void validatePositiveResponse(SMessage response, Message req, SRRset key_rrset) {
        Name qname = req.getQuestion().getName();
        int qtype = req.getQuestion().getType();

        SMessage m = response;

        // validate the ANSWER section - this will be the answer itself
        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);

        Name wc = null;
        boolean wcNSEC_ok = false;
        boolean dname = false;
        List<NSEC3Record> nsec3s = null;

        for (int i = 0; i < rrsets.length; i++) {
            // Skip the CNAME following a (validated) DNAME.
            // Because of the normalization routines in NameserverClient, there
            // will always be an unsigned CNAME following a DNAME (unless
            // qtype=DNAME).
            if (dname && rrsets[i].getType() == Type.CNAME) {
                dname = false;
                continue;
            }

            // Verify the answer rrset.
            SecurityStatus status = valUtils.verifySRRset(rrsets[i], key_rrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                log.debug("Postive response has failed ANSWER rrset: " + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // Check to see if the rrset is the result of a wildcard expansion.
            // If
            // so, an additional check will need to be made in the authority
            // section.
            wc = ValUtils.rrsetWildcard(rrsets[i]);

            // Notice a DNAME that should be followed by an unsigned CNAME.
            if (qtype != Type.DNAME && rrsets[i].getType() == Type.DNAME) {
                dname = true;
            }
        }

        // validate the AUTHORITY section as well - this will generally be the
        // NS
        // rrset (which could be missing, no problem)
        rrsets = m.getSectionRRsets(Section.AUTHORITY);
        for (int i = 0; i < rrsets.length; i++) {
            SecurityStatus status = valUtils.verifySRRset(rrsets[i], key_rrset);
            // If anything in the authority section fails to be secure, we have
            // a
            // bad message.
            if (status != SecurityStatus.SECURE) {
                log.debug("Postive response has failed AUTHORITY rrset: " + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // If this is a positive wildcard response, and we have a (just
            // verified) NSEC record, try to use it to 1) prove that qname
            // doesn't
            // exist and 2) that the correct wildcard was used.
            if (wc != null && rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNameError(nsec, qname, key_rrset.getName())) {
                    Name nsec_wc = ValUtils.nsecWildcard(qname, nsec);
                    if (!wc.equals(nsec_wc)) {
                        log.debug("Postive wildcard response wasn't generated " + "by the correct wildcard");
                        m.setStatus(SecurityStatus.BOGUS);
                        return;
                    }
                    wcNSEC_ok = true;
                }
            }

            // Otherwise, if this is a positive wildcard response and we have
            // NSEC3
            // records, collect them.
            if (wc != null && rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null)
                    nsec3s = new ArrayList<NSEC3Record>();
                nsec3s.add((NSEC3Record) rrsets[i].first());
            }
        }

        // If this was a positive wildcard response that we haven't already
        // proven, and we have NSEC3 records, try to prove it using the NSEC3
        // records.
        if (wc != null && !wcNSEC_ok && nsec3s != null) {
            if (NSEC3ValUtils.proveWildcard(nsec3s, qname, key_rrset.getName(), wc)) {
                wcNSEC_ok = true;
            }
        }

        // If after all this, we still haven't proven the positive wildcard
        // response, fail.
        if (wc != null && !wcNSEC_ok) {
            log.debug("positive response was wildcard expansion and " + "did not prove original data did not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        log.trace("Successfully validated postive response");
        m.setStatus(SecurityStatus.SECURE);
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
     * @param key_rrset The trusted DNSKEY rrset that matches the signer of the
     *            answer.
     */
    private void validateAnyResponse(SMessage response, Message req, SRRset key_rrset) {
        int qtype = req.getQuestion().getType();

        if (qtype != Type.ANY)
            throw new IllegalArgumentException("ANY validation called on non-ANY response.");

        SMessage m = response;

        // validate the ANSWER section.
        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);
        for (int i = 0; i < rrsets.length; i++) {
            SecurityStatus status = valUtils.verifySRRset(rrsets[i], key_rrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                log.debug("Postive response has failed ANSWER rrset: " + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

        // validate the AUTHORITY section as well - this will be the NS rrset
        // (which could be missing, no problem)
        rrsets = m.getSectionRRsets(Section.AUTHORITY);
        for (int i = 0; i < rrsets.length; i++) {
            SecurityStatus status = valUtils.verifySRRset(rrsets[i], key_rrset);
            // If anything in the authority section fails to be secure, we have
            // a
            // bad message.
            if (status != SecurityStatus.SECURE) {
                log.debug("Postive response has failed AUTHORITY rrset: " + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
        }

        log.trace("Successfully validated postive ANY response");
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
     * @param key_rrset The trusted DNSKEY rrset that signs this response.
     */
    private void validateNodataResponse(SMessage response, Message req, SRRset key_rrset) {
        Name qname = req.getQuestion().getName();
        int qtype = req.getQuestion().getType();

        SMessage m = response;

        // Since we are here, there must be nothing in the ANSWER section to
        // validate. (Note: CNAME/DNAME responses will not directly get here --
        // instead they are broken down into individual CNAME/DNAME/final answer
        // responses.)

        // validate the AUTHORITY section
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);

        boolean hasValidNSEC = false; // If true, then the NODATA has been
                                      // proven.
        Name ce = null; // for wildcard nodata responses. This is the proven
                        // closest encloser.
        NSECRecord wc = null; // for wildcard nodata responses. This is the
                              // wildcard NSEC.
        List<NSEC3Record> nsec3s = null; // A collection of NSEC3 RRs found in
                                         // the authority
        // section.
        Name nsec3Signer = null; // The RRSIG signer field for the NSEC3 RRs.

        for (int i = 0; i < rrsets.length; i++) {
            SecurityStatus status = valUtils.verifySRRset(rrsets[i], key_rrset);
            if (status != SecurityStatus.SECURE) {
                log.debug("NODATA response has failed AUTHORITY rrset: " + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }

            // If we encounter an NSEC record, try to use it to prove NODATA.
            // This needs to handle the ENT NODATA case.
            if (rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();
                if (ValUtils.nsecProvesNodata(nsec, qname, qtype)) {
                    hasValidNSEC = true;
                    if (nsec.getName().isWild())
                        wc = nsec;
                }
                else if (ValUtils.nsecProvesNameError(nsec, qname, rrsets[i].getSignerName())) {
                    ce = ValUtils.closestEncloser(qname, nsec);
                }
            }

            // Collect any NSEC3 records present.
            if (rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null)
                    nsec3s = new ArrayList<NSEC3Record>();
                nsec3s.add((NSEC3Record) rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        // check to see if we have a wildcard NODATA proof.

        // The wildcard NODATA is 1 NSEC proving that qname does not exists (and
        // also proving what the closest encloser is), and 1 NSEC showing the
        // matching wildcard, which must be *.closest_encloser.
        if (ce != null || wc != null) {
            try {
                Name wc_name = new Name("*", ce);
                if (!wc_name.equals(wc.getName())) {
                    hasValidNSEC = false;
                }
            }
            catch (TextParseException e) {
                log.error(e);
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (!hasValidNSEC && nsec3s != null && nsec3s.size() > 0) {
            // try to prove NODATA with our NSEC3 record(s)
            hasValidNSEC = NSEC3ValUtils.proveNodata(nsec3s, qname, qtype, nsec3Signer);
        }

        if (!hasValidNSEC) {
            log.debug("NODATA response failed to prove NODATA " + "status with NSEC/NSEC3");
            log.trace("Failed NODATA:\n" + m);
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }
        log.trace("sucessfully validated NODATA response.");
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
     * @param response The response to validate.
     * @param request The request that generated this response.
     * @param key_rrset The trusted DNSKEY rrset that signs this response.
     */
    private void validateNameErrorResponse(SMessage response, Message req, SRRset key_rrset) {
        Name qname = req.getQuestion().getName();

        SMessage m = response;

        // FIXME: should we check to see if there is anything in the answer
        // section? if so, what should the result be?

        // Validate the authority section -- all RRsets in the authority section
        // must be signed and valid.
        // In addition, the NSEC record(s) must prove the NXDOMAIN condition.

        boolean hasValidNSEC = false;
        boolean hasValidWCNSEC = false;
        SRRset[] rrsets = m.getSectionRRsets(Section.AUTHORITY);
        List<NSEC3Record> nsec3s = null;
        Name nsec3Signer = null;

        for (int i = 0; i < rrsets.length; i++) {
            SecurityStatus status = valUtils.verifySRRset(rrsets[i], key_rrset);
            if (status != SecurityStatus.SECURE) {
                log.debug("NameError response has failed AUTHORITY rrset: " + rrsets[i]);
                m.setStatus(SecurityStatus.BOGUS);
                return;
            }
            if (rrsets[i].getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord) rrsets[i].first();

                if (ValUtils.nsecProvesNameError(nsec, qname, rrsets[i].getSignerName())) {
                    hasValidNSEC = true;
                }
                if (ValUtils.nsecProvesNoWC(nsec, qname, rrsets[i].getSignerName())) {
                    hasValidWCNSEC = true;
                }
            }
            if (rrsets[i].getType() == Type.NSEC3) {
                if (nsec3s == null)
                    nsec3s = new ArrayList<NSEC3Record>();
                nsec3s.add((NSEC3Record) rrsets[i].first());
                nsec3Signer = rrsets[i].getSignerName();
            }
        }

        NSEC3ValUtils.stripUnknownAlgNSEC3s(nsec3s);

        if (nsec3s != null && nsec3s.size() > 0) {
            log.debug("Validating nxdomain: using NSEC3 records");
            // Attempt to prove name error with nsec3 records.

            if (NSEC3ValUtils.allNSEC3sIgnoreable(nsec3s, key_rrset)) {
                log.debug("all NSEC3s were validated but ignored.");
                m.setStatus(SecurityStatus.INSECURE);
                return;
            }

            hasValidNSEC = NSEC3ValUtils.proveNameError(nsec3s, qname, nsec3Signer);

            // Note that we assume that the NSEC3ValUtils proofs encompass the
            // wildcard part of the proof.
            hasValidWCNSEC = hasValidNSEC;
        }

        // If the message fails to prove either condition, it is bogus.
        if (!hasValidNSEC) {
            log.debug("NameError response has failed to prove: " + "qname does not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        if (!hasValidWCNSEC) {
            log.debug("NameError response has failed to prove: " + "covering wildcard does not exist");
            m.setStatus(SecurityStatus.BOGUS);
            return;
        }

        // Otherwise, we consider the message secure.
        log.trace("successfully validated NAME ERROR response.");
        m.setStatus(SecurityStatus.SECURE);
    }

    // ----------------- Resolution Support -----------------------

    private void processRequest(DNSEvent event) {
        log.trace("processing request: <" + event.getRequest() + ">");

        // Add a module state object to every request.
        // Locally generated requests will already have state.
        ValEventState state = event.getModuleState();
        if (state == null) {
            state = new ValEventState();
            event.setModuleState(state);
        }

        // (Possibly) modify the request to add the CD bit.
        prepareRequest(event.getRequest());

        // Send the request along by using a local copy of the request
        Message local_request = (Message) event.getRequest().clone();
        try {
            Message resp = headResolver.send(local_request);
            event.setResponse(new SMessage(resp));
            processResponse(event);
        }
        catch (SocketTimeoutException e) {
            log.error("Query timed out, returning fail", e);
            event.setResponse(Util.errorMessage(local_request, Rcode.SERVFAIL));
        }
        catch (UnknownHostException e) {
            log.error("failed to send query", e);
            event.setResponse(Util.errorMessage(local_request, Rcode.SERVFAIL));
        }
        catch (IOException e) {
            log.error("failed to send query", e);
            event.setResponse(Util.errorMessage(local_request, Rcode.SERVFAIL));
        }
    }

    private void processResponse(DNSEvent event) {
        log.trace("processing response");
        handleResponse(event, event.getModuleState());
    }

    private void handleResponse(DNSEvent event, ValEventState state) {
        boolean cont = true;

        // Loop on event states. If a processing routine returns false, that
        // means
        // to drop the event. True means to continue. Responses that should be
        // propagated back must end in the "FINISHED" state.

        while (cont) {
            switch (state.state) {
                case ValEventState.INIT_STATE:
                    cont = processInit(event, state);
                    break;
                case ValEventState.PRIME_RESP_STATE:
                    cont = processPrimeResponse(event, state);
                    break;
                case ValEventState.FINDKEY_STATE:
                    cont = processFindKey(event, state);
                    break;
                case ValEventState.FINDKEY_DS_RESP_STATE:
                    cont = processDSResponse(event, state);
                    break;
                case ValEventState.FINDKEY_DNSKEY_RESP_STATE:
                    cont = processDNSKEYResponse(event, state);
                    break;
                case ValEventState.VALIDATE_STATE:
                    cont = processValidate(event, state);
                    break;
                case ValEventState.CNAME_STATE:
                    cont = processCNAME(event, state);
                    break;
                case ValEventState.CNAME_RESP_STATE:
                    cont = processCNAMEResponse(event, state);
                    break;
                case ValEventState.CNAME_ANS_RESP_STATE:
                    cont = processCNAMEAnswer(event, state);
                    break;
                case ValEventState.FINISHED_STATE:
                    cont = processFinishedState(event, state);
                    break;
                default:
                    log.error("unknown validation event state: " + state.state);
                    cont = false;
                    break;
            }
        }
    }

    /**
     * Process the INIT state. First tier responses start in the INIT state.
     * This is where they are vetted for validation suitability, and the initial
     * key search is done.
     * 
     * Currently, events the come through this routine will be either promoted
     * to FINISHED/CNAME_RESP (no validation needed), FINDKEY (next step to
     * validation), or will be (temporarily) retired and a new priming request
     * event will be generated.
     * 
     * @param event The response event being processed.
     * @param state The state object associated with the event.
     * @return true if the event should be processed further on return, false if
     *         not.
     */
    private boolean processInit(DNSEvent event, ValEventState state) {
        SMessage resp = event.getResponse();
        Message origRequest = event.getOrigRequest();
        Message req = event.getRequest();

        if (!needsValidation(resp, origRequest)) {
            state.state = state.finalState;
            return true;
        }

        Name qname = req.getQuestion().getName();
        int qclass = req.getQuestion().getDClass();

        state.trustAnchorRRset = trustAnchors.find(qname, qclass);

        if (state.trustAnchorRRset == null) {
            // response isn't under a trust anchor, so we cannot validate.
            state.state = state.finalState;
            return true;
        }

        // Determine the signer/lookup name
        state.signerName = valUtils.findSigner(resp, req);
        Name lookupName = (state.signerName == null) ? qname : state.signerName;

        state.keyEntry = keyCache.find(lookupName, qclass);

        if (state.keyEntry == null) {
            // fire off a trust anchor priming query.
            primeTrustAnchor(event, state.trustAnchorRRset);
            // and otherwise, don't continue processing this event.
            // (it will be reactivated when the priming query returns).
            state.state = ValEventState.FINDKEY_STATE;
            return false;
        }
        else if (state.keyEntry.isNull()) {
            // response is under a null key, so we cannot validate
            // However, we do set the status to INSECURE, since it is
            // essentially
            // proven insecure.
            resp.setStatus(SecurityStatus.INSECURE);
            state.state = state.finalState;
            return true;
        }

        // otherwise, we have our "closest" cached key -- continue processing in
        // the next state.
        state.state = ValEventState.FINDKEY_STATE;
        return true;
    }

    /**
     * Evaluate the response to a priming request.
     * 
     * @param response The response to the priming request.
     * @param trustAnchor The trust anchor (in DS or DNSKEY form) that is being
     *            primed.
     * @return a KeyEntry. This will either contain a validated DNSKEY rrset, or
     *         represent a Null key (query failed, but validation did not), or a
     *         Bad key (validation failed).
     */
    private KeyEntry primeResponseToKE(SMessage response, SRRset trustAnchor) {
        Name qname = trustAnchor.getName();
        int qtype = trustAnchor.getType();
        int qclass = trustAnchor.getDClass();

        SRRset dnskey_rrset = response.findAnswerRRset(qname, Type.DNSKEY, qclass);

        // If the priming query didn't return a DNSKEY response, then we
        // temporarily consider this a "null" key.
        if (dnskey_rrset == null) {
            log.debug("Failed to prime trust anchor: " + qname + "/" + Type.string(qtype) + "/" + DClass.string(qclass) + " -- could not fetch DNSKEY rrset");

            keyCache.store(qname, qclass, DEFAULT_TA_NULL_KEY_TTL);
            return KeyEntry.newNullKeyEntry(qname, qclass, DEFAULT_TA_NULL_KEY_TTL);
        }

        SecurityStatus status;
        if (qtype == Type.DS) {
            KeyEntry dnskey_entry = valUtils.verifyNewDNSKEYs(dnskey_rrset, trustAnchor);
            if (dnskey_entry.isGood()) {
                status = SecurityStatus.SECURE;
            }
            else {
                status = SecurityStatus.BOGUS;
            }
        }
        else if (qtype == Type.DNSKEY) {
            status = valUtils.verifySRRset(dnskey_rrset, trustAnchor);
        }
        else {
            status = SecurityStatus.BOGUS;
        }

        if (status != SecurityStatus.SECURE) {
            log.debug("Could not prime trust anchor: " + qname + "/" + Type.string(qtype) + "/" + DClass.string(qclass) + " -- DNSKEY rrset did not verify");

            // no or a bad answer to a trust anchor means we cannot continue
            keyCache.store(qname, qclass, DEFAULT_TA_NULL_KEY_TTL);
            return KeyEntry.newBadKeyEntry(qname, qclass);
        }

        log.debug("Successfully primed trust anchor: " + qname + "/" + Type.string(qtype) + "/" + DClass.string(qclass));

        keyCache.store(dnskey_rrset);
        return KeyEntry.newKeyEntry(dnskey_rrset);
    }

    /**
     * Process the response to a priming request. This will revive the dependent
     * event and set its keyEntry.
     * 
     * @param event The response event to the priming event.
     * @param state The state object attached to that event.
     * @return false, since these events do not need further processing.
     */
    private boolean processPrimeResponse(DNSEvent event, ValEventState state) {
        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        SMessage resp = event.getResponse();

        // Fetch and validate the keyEntry that corresponds to the current trust
        // anchor.
        forState.keyEntry = primeResponseToKE(resp, forState.trustAnchorRRset);

        // If the result of the prime is a null key, skip the FINDKEY state.
        if (forState.keyEntry.isNull() || forState.keyEntry.isBad()) {
            forState.state = ValEventState.VALIDATE_STATE;
        }

        // Continue processing our 'forEvent'. This event is finished.
        processResponse(forEvent);

        return false;
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
        // different
        // state.
        Message req = event.getRequest();
        Name qname = req.getQuestion().getName();
        int qclass = req.getQuestion().getDClass();

        Name targetKeyName = state.signerName;
        if (targetKeyName == null) {
            targetKeyName = qname;
        }

        Name currentKeyName = state.keyEntry.getName();

        // If our current key entry matches our target, then we are done.
        if (currentKeyName.equals(targetKeyName)) {
            state.state = ValEventState.VALIDATE_STATE;
            return true;
        }

        if (state.emptyDSName != null)
            currentKeyName = state.emptyDSName;

        // Caculate the next lookup name.
        int target_labels = targetKeyName.labels();
        int current_labels = currentKeyName.labels();
        int l = target_labels - current_labels - 1;

        Name nextKeyName = new Name(targetKeyName, l);
        log.trace("findKey: targetKeyName = " + targetKeyName + ", currentKeyName = " + currentKeyName + ", nextKeyName = " + nextKeyName);
        // The next step is either to query for the next DS, or to query for the
        // next DNSKEY.

        if (state.dsRRset == null || !state.dsRRset.getName().equals(nextKeyName)) {
            Message ds_request = generateLocalRequest(nextKeyName, Type.DS, qclass);
            DNSEvent ds_event = generateLocalEvent(event, ds_request, ValEventState.FINDKEY_DS_RESP_STATE, ValEventState.FINDKEY_DS_RESP_STATE);
            processRequest(ds_event);
            return false;
        }

        // Otherwise, it is time to query for the DNSKEY
        Message dnskey_request = generateLocalRequest(state.dsRRset.getName(), Type.DNSKEY, qclass);
        DNSEvent dnskey_event = generateLocalEvent(event, dnskey_request, ValEventState.FINDKEY_DNSKEY_RESP_STATE, ValEventState.FINDKEY_DNSKEY_RESP_STATE);
        processRequest(dnskey_event);

        return false;
    }

    /**
     * Given a DS response, the DS request, and the current key rrset, validate
     * the DS response, returning a KeyEntry.
     * 
     * @param response The DS response.
     * @param request The DS request.
     * @param key_rrset The current DNSKEY rrset from the forEvent state.
     * 
     * @return A KeyEntry, bad if the DS response fails to validate, null if the
     *         DS response indicated an end to secure space, good if the DS
     *         validated. It returns null if the DS response indicated that the
     *         request wasn't a delegation point.
     */
    private KeyEntry dsResponseToKE(SMessage response, Message request, SRRset key_rrset) {
        Name qname = request.getQuestion().getName();
        int qclass = request.getQuestion().getDClass();

        SecurityStatus status;
        int subtype = ValUtils.classifyResponse(response);

        KeyEntry bogusKE = KeyEntry.newBadKeyEntry(qname, qclass);
        switch (subtype) {
            case ValUtils.POSITIVE:
                SRRset ds_rrset = response.findAnswerRRset(qname, Type.DS, qclass);
                // If there was no DS rrset, then we have mis-classified this
                // message.
                if (ds_rrset == null) {
                    log.warn("POSITIVE DS response was missing DS!  This is a bug!");
                    return bogusKE;
                }
                // Verify only returns BOGUS or SECURE. If the rrset is bogus,
                // then we are done.
                status = valUtils.verifySRRset(ds_rrset, key_rrset);
                if (status == SecurityStatus.BOGUS) {
                    log.debug("DS rrset in DS response did not verify");
                    return bogusKE;
                }

                // Otherwise, we return the positive response.
                log.trace("DS rrset was good.");
                return KeyEntry.newKeyEntry(ds_rrset);

            case ValUtils.NODATA:
                // NODATA means that the qname exists, but that there was no DS.
                // This is a pretty normal case.
                SRRset nsec_rrset = response.findRRset(qname, Type.NSEC, qclass, Section.AUTHORITY);

                // If we have a NSEC at the same name, it must prove one of two
                // things
                // --
                // 1) this is a delegation point and there is no DS
                // 2) this is not a delegation point
                if (nsec_rrset != null) {
                    // The NSEC must verify, first of all.
                    status = valUtils.verifySRRset(nsec_rrset, key_rrset);
                    if (status != SecurityStatus.SECURE) {
                        log.debug("NSEC RRset for the referral did not verify.");
                        return bogusKE;
                    }

                    NSECRecord nsec = (NSECRecord) nsec_rrset.first();
                    switch (ValUtils.nsecProvesNoDS(nsec, qname)) {
                        case BOGUS: // something was wrong.
                            log.debug("NSEC RRset for the referral did not prove no DS.");
                            return bogusKE;
                        case INSECURE: // this wasn't a
                                       // delegation point.
                            log.debug("NSEC RRset for the referral proved " + "not a delegation point");
                            return null;
                        case SECURE: // this proved no DS.
                            log.debug("NSEC RRset for the referral proved no DS.");
                            return KeyEntry.newNullKeyEntry(qname, qclass, nsec_rrset.getTTL());
                        default:
                            throw new RuntimeException("unexpected security status");
                    }
                }

                // Otherwise, there is no NSEC at qname. This could be an ENT.
                // If not,
                // this is broken.
                SRRset[] nsec_rrsets = response.getSectionRRsets(Section.AUTHORITY, Type.NSEC);
                for (int i = 0; i < nsec_rrsets.length; i++) {
                    status = valUtils.verifySRRset(nsec_rrsets[i], key_rrset);
                    if (status != SecurityStatus.SECURE) {
                        log.debug("NSEC for empty non-terminal did not verify.");
                        return bogusKE;
                    }
                    NSECRecord nsec = (NSECRecord) nsec_rrsets[i].first();
                    if (ValUtils.nsecProvesNodata(nsec, qname, Type.DS)) {
                        log.debug("NSEC for empty non-terminal proved no DS.");
                        return KeyEntry.newNullKeyEntry(qname, qclass, nsec_rrsets[i].getTTL());
                    }
                }

                // Or it could be using NSEC3.
                SRRset[] nsec3_rrsets = response.getSectionRRsets(Section.AUTHORITY, Type.NSEC3);
                List<NSEC3Record> nsec3s = new ArrayList<NSEC3Record>();
                Name nsec3Signer = null;
                long nsec3TTL = -1;
                if (nsec3_rrsets != null && nsec3_rrsets.length > 0) {
                    // Attempt to prove no DS with NSEC3s.
                    for (int i = 0; i < nsec3_rrsets.length; i++) {
                        status = valUtils.verifySRRset(nsec3_rrsets[i], key_rrset);
                        if (status != SecurityStatus.SECURE) {
                            // FIXME: we could just fail here -- there is an
                            // invalid rrset -- but is more robust to skip like
                            // we are.
                            log.debug("skipping bad nsec3");
                            continue;
                        }

                        NSEC3Record nsec3 = (NSEC3Record) nsec3_rrsets[i].first();
                        nsec3Signer = nsec3_rrsets[i].getSignerName();
                        if (nsec3TTL < 0 || nsec3_rrsets[i].getTTL() < nsec3TTL)
                            nsec3TTL = nsec3_rrsets[i].getTTL();
                        nsec3s.add(nsec3);
                    }

                    switch (NSEC3ValUtils.proveNoDS(nsec3s, qname, nsec3Signer)) {
                        case BOGUS:
                            log.debug("nsec3s proved bogus.");
                            return bogusKE;
                        case INSECURE:
                            log.debug("nsec3s proved no delegation.");
                            return null;
                        case SECURE:
                            log.debug("nsec3 proved no ds.");
                            return KeyEntry.newNullKeyEntry(qname, qclass, nsec3TTL);
                        default:
                            throw new RuntimeException("unexpected security status");
                    }
                }
                // Apparently, no available NSEC/NSEC3 proved NODATA, so this is
                // BOGUS.
                log.debug("ran out of options, so return bogus");
                return bogusKE;

            case ValUtils.NAMEERROR:
                // NAMEERRORs at this point pretty much break validation
                log.debug("DS response was NAMEERROR, thus bogus.");
                return bogusKE;
        }
        // We've encountered an unhandled classification for this response.
        log.debug("Encountered an unhandled type of DS response, thus bogus.");
        return bogusKE;
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
        Message ds_request = event.getRequest();
        SMessage ds_resp = event.getResponse();

        Name qname = ds_request.getQuestion().getName();

        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        forState.emptyDSName = null;
        forState.dsRRset = null;

        KeyEntry dsKE = dsResponseToKE(ds_resp, ds_request, forState.keyEntry.getRRset());

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
            // or
            // null) should have been logged by dsResponseToKE.
            forState.keyEntry = dsKE;
            // The FINDKEY phase has ended, so move on.
            forState.state = ValEventState.VALIDATE_STATE;
        }

        processResponse(forEvent);
        return false;
    }

    private boolean processDNSKEYResponse(DNSEvent event, ValEventState state) {
        Message dnskey_request = event.getRequest();
        SMessage dnskey_resp = event.getResponse();
        Name qname = dnskey_request.getQuestion().getName();
        int qclass = dnskey_request.getQuestion().getDClass();

        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        SRRset ds_rrset = forState.dsRRset;
        SRRset dnskey_rrset = dnskey_resp.findAnswerRRset(qname, Type.DNSKEY, qclass);

        if (dnskey_rrset == null) {
            // If the DNSKEY rrset was missing, this is the end of the line.
            log.debug("Missing DNSKEY RRset in response to DNSKEY query.");
            forState.keyEntry = KeyEntry.newBadKeyEntry(qname, qclass);
            forState.state = ValEventState.VALIDATE_STATE;
            processResponse(forEvent);
            return false;
        }

        forState.keyEntry = valUtils.verifyNewDNSKEYs(dnskey_rrset, ds_rrset);

        // If the key entry isBad or isNull, then we can move on to the next
        // state.
        if (!forState.keyEntry.isGood()) {
            if (log.isDebugEnabled() && forState.keyEntry.isBad()) {
                log.debug("Did not match a DS to a DNSKEY, thus bogus.");
            }
            forState.state = ValEventState.VALIDATE_STATE;
            processResponse(forEvent);
            return false;
        }

        // The DNSKEY validated, so cache it as a trusted key rrset.
        keyCache.store(forState.keyEntry.getRRset());

        // If good, we stay in the FINDKEY state.
        processResponse(forEvent);
        return false;
    }

    private boolean processValidate(DNSEvent event, ValEventState state) {
        Message req = event.getRequest();
        SMessage resp = event.getResponse();

        // This is the default next state.
        state.state = state.finalState;

        // signerName being null is the indicator that this response was
        // unsigned
        if (state.signerName == null) {
            log.debug("processValidate: event " + event + " has no signerName.");
            // Unsigned responses must be underneath a "null" key entry.
            if (state.keyEntry.isNull()) {
                log.debug("Unsigned response was proved to be validly INSECURE");
                resp.setStatus(SecurityStatus.INSECURE);
                return true;
            }
            log.debug("Could not establish validation of " + "INSECURE status of unsigned response.");
            resp.setStatus(SecurityStatus.BOGUS);
            return true;
        }

        if (state.keyEntry.isBad()) {
            log.debug("Could not establish a chain of trust to keys for: " + state.keyEntry.getName());
            resp.setStatus(SecurityStatus.BOGUS);
            return true;
        }

        if (state.keyEntry.isNull()) {
            log.debug("Verified that response is INSECURE");
            resp.setStatus(SecurityStatus.INSECURE);
            return true;
        }

        int subtype = ValUtils.classifyResponse(resp);
        SRRset key_rrset = state.keyEntry.getRRset();

        switch (subtype) {
            case ValUtils.POSITIVE:
                log.trace("Validating a positive response");
                validatePositiveResponse(resp, req, key_rrset);
                break;
            case ValUtils.NODATA:
                log.trace("Validating a nodata response");
                validateNodataResponse(resp, req, key_rrset);
                break;
            case ValUtils.NAMEERROR:
                log.trace("Validating a nxdomain response");
                validateNameErrorResponse(resp, req, key_rrset);
                break;
            case ValUtils.CNAME:
                log.trace("Validating a cname response");
                // forward on to the special CNAME state for this.
                state.state = ValEventState.CNAME_STATE;
                break;
            case ValUtils.ANY:
                log.trace("Validating a postive ANY response");
                validateAnyResponse(resp, req, key_rrset);
                break;
            default:
                log.error("unhandled response subtype: " + subtype);
        }

        return true;
    }

    /**
     * This state is used for validating CNAME-type responses -- i.e., responses
     * that have CNAME chains.
     * 
     * It primarily is responsible for breaking down the response into a series
     * of separately validated queries & responses.
     * 
     * @param event
     * @param state
     * @return
     */
    private boolean processCNAME(DNSEvent event, ValEventState state) {
        Message req = event.getRequest();

        Name qname = req.getQuestion().getName();
        int qtype = req.getQuestion().getType();
        int qclass = req.getQuestion().getDClass();

        SMessage m = event.getResponse();

        if (state.cnameSname == null)
            state.cnameSname = qname;

        // We break the chain down by re-querying for the specific CNAME or
        // DNAME
        // (or final answer).
        SRRset[] rrsets = m.getSectionRRsets(Section.ANSWER);

        while (state.cnameIndex < rrsets.length) {
            SRRset rrset = rrsets[state.cnameIndex++];
            Name rname = rrset.getName();
            int rtype = rrset.getType();

            // Skip DNAMEs -- prefer to query for the generated CNAME,
            if (rtype == Type.DNAME && qtype != Type.DNAME)
                continue;

            // Set the SNAME if we are dealing with a CNAME
            if (rtype == Type.CNAME) {
                CNAMERecord cname = (CNAMERecord) rrset.first();
                state.cnameSname = cname.getTarget();
            }

            // Note if the current rrset is the answer. In that case, we want to
            // set
            // the final state differently.
            // For non-answers, the response ultimately comes back here.
            int final_state = ValEventState.CNAME_RESP_STATE;
            if (isAnswerRRset(rrset.getName(), rtype, state.cnameSname, qtype, Section.ANSWER)) {
                // If this is an answer, however, break out of this loop.
                final_state = ValEventState.CNAME_ANS_RESP_STATE;
            }

            // Generate the sub-query.
            Message localRequest = generateLocalRequest(rname, rtype, qclass);
            DNSEvent localEvent = generateLocalEvent(event, localRequest, ValEventState.INIT_STATE, final_state);

            // ...and send it along.
            processRequest(localEvent);
            return false;
        }

        // Something odd has happened if we get here.
        log.warn("processCNAME: encountered unknown issue handling a CNAME chain.");
        return false;
    }

    private boolean processCNAMEResponse(DNSEvent event, ValEventState state) {
        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        SMessage resp = event.getResponse();
        if (resp.getStatus() != SecurityStatus.SECURE) {
            forEvent.getResponse().setStatus(resp.getStatus());
            forState.state = forState.finalState;
            handleResponse(forEvent, forState);
            return false;
        }

        forState.state = ValEventState.CNAME_STATE;
        handleResponse(forEvent, forState);
        return false;
    }

    private boolean processCNAMEAnswer(DNSEvent event, ValEventState state) {
        DNSEvent forEvent = event.forEvent();
        ValEventState forState = forEvent.getModuleState();

        SMessage resp = event.getResponse();
        SMessage forResp = forEvent.getResponse();

        forResp.setStatus(resp.getStatus());

        forState.state = forState.finalState;
        handleResponse(forEvent, forState);
        return false;
    }

    private boolean processFinishedState(DNSEvent event, ValEventState state) {
        normalizeResponse(event, state);

        return false;
    }

    // Resolver-interface implementation --------------------------------------
    /**
     * Forwards the data to the head resolver passed at construction time.
     * @see org.xbill.DNS.Resolver#setPort(int)
     */
    public void setPort(int port) {
        headResolver.setPort(port);
    }

    /** Forwards the data to the head resolver passed at construction time.
     * @see org.xbill.DNS.Resolver#setTCP(boolean)
     */
    public void setTCP(boolean flag) {
        headResolver.setTCP(flag);
    }

    /**
     * This is a no-op, truncation is never ignored.
     * @param flag unused
     */
    public void setIgnoreTruncation(boolean flag) {
    }

    /**
     * This is a no-op, EDNS is always set to level 0.
     * @param level unused
     */
    public void setEDNS(int level) {
    }

    /**
     * The method is forwarded to the resolver, but always ensure that the level is 0 and the flags contains DO.
     * @param level unused, always set to 0.
     * @see org.xbill.DNS.Resolver#setEDNS(int, int, int, java.util.List)
     */
    public void setEDNS(int level, int payloadSize, int flags, @SuppressWarnings("rawtypes") List options) {
        headResolver.setEDNS(0, payloadSize, flags | ExtendedFlags.DO, options);
    }

    /**
     * Forwards the data to the head resolver passed at construction time.
     * @see org.xbill.DNS.Resolver#setTSIGKey(org.xbill.DNS.TSIG)
     */
    public void setTSIGKey(TSIG key) {
        headResolver.setTSIGKey(key);
    }

    public void setTimeout(int secs, int msecs) {
        headResolver.setTimeout(secs, msecs);
    }

    public void setTimeout(int secs) {
        headResolver.setTimeout(secs);
    }

    public Message send(Message request) throws IOException {
        DNSEvent event = new DNSEvent(request);

        // This should synchronously process the request, based on the way the
        // resolver tail is configured.
        processRequest(event);

        return event.getResponse().getMessage();
    }

    public Object sendAsync(Message query, ResolverListener listener) {
        throw new RuntimeException("Not implemented");
    }
}
