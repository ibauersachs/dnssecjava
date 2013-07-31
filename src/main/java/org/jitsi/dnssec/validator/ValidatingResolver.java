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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.jitsi.dnssec.SMessage;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.jitsi.dnssec.R;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
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
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * This resolver validates responses with DNSSEC.
 */
public class ValidatingResolver implements Resolver {
    /**
     * The QCLASS being used for the injection of the reason why the validator
     * came to the returned result.
     */
    public static final int VALIDATION_REASON_QCLASS = 65280;

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

    /**
     * The local NSEC3 validation utilities.
     */
    private NSEC3ValUtils n3valUtils;

    /**
     * The resolver that performs the actual DNS lookups.
     */
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
        this.n3valUtils = new NSEC3ValUtils();
        this.trustAnchors = new TrustAnchorStore();
    }

    // ---------------- Module Initialization -------------------
    /**
     * Initialize the module. The only recognized configuration value is
     * <tt>org.jitsi.dnssec.trust_anchor_file</tt>.
     * 
     * @param config The configuration data for this module.
     * @throws IOException When the file specified in the config does not exist
     *             or cannot be read.
     */
    public void init(Properties config) throws IOException {
        this.keyCache.init(config);
        this.n3valUtils.init(config);

        // Load trust anchors
        String s = config.getProperty("org.jitsi.dnssec.trust_anchor_file");
        if (s != null) {
            logger.debug("reading trust anchor file file: " + s);
            loadTrustAnchors(new FileInputStream(s));
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

    /**
     * Given a "postive" response -- a response that contains an answer to the
     * question, and no CNAME chain, validate this response. This generally
     * consists of verifying the answer RRset and the authority RRsets.
     * 
     * Note that by the time this method is called, the process of finding the
     * trusted DNSKEY rrset that signs this response must already have been
     * completed.
     * 
     * @param request The request that generated this response.
     * @param response The response to validate.
     */
    private void validatePositiveResponse(Message request, SMessage response) {
        int qtype = request.getQuestion().getType();

        // validate the ANSWER section - this will be the answer itself
        Map<Name, Name> wcs = new HashMap<Name, Name>(1);
        DNAMERecord dname = null;
        List<NSEC3Record> nsec3s = null;
        List<NSECRecord> nsecs = null;

        SRRset keyRrset = null;
        for (SRRset set : response.getSectionRRsets(Section.ANSWER)) {
            // Validate the CNAME following a (validated) DNAME is correctly
            // synthesized.
            if (set.getType() == Type.CNAME && dname != null) {
                if (set.size() > 1) {
                    response.setBogus(R.get("failed.synthesize.multiple"));
                    return;
                }

                CNAMERecord cname = (CNAMERecord)set.first();
                try {
                    Name expected = Name.concatenate(cname.getName().relativize(dname.getName()), dname.getTarget());
                    if (!expected.equals(cname.getTarget())) {
                        response.setBogus(R.get("failed.synthesize.nomatch", cname.getTarget(), expected));
                        return;
                    }
                }
                catch (NameTooLongException e) {
                    response.setBogus(R.get("failed.synthesize.toolong"));
                    return;
                }

                set.setSecurityStatus(SecurityStatus.SECURE);
                dname = null;
                continue;
            }

            // Verify the answer rrset.
            KeyEntry ke = this.prepareFindKey(set, request);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            keyRrset = ke.getRRset();
            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.answer.positive", set));
                return;
            }

            // Check to see if the rrset is the result of a wildcard expansion.
            // If so, an additional check will need to be made in the authority
            // section.
            Name wc = ValUtils.rrsetWildcard(set);
            if (wc != null && !set.getName().equals(wc)) {
                wcs.put(set.getName(), wc);
            }

            // Notice a DNAME that should be followed by an unsigned CNAME.
            if (qtype != Type.DNAME && set.getType() == Type.DNAME) {
                dname = (DNAMERecord)set.first();
            }
        }

        // validate the AUTHORITY section as well - this will generally be the
        // NS rrset (which could be missing, no problem)
        for (SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, request);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            keyRrset = ke.getRRset();
            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            // If anything in the authority section fails to be secure, we have
            // a bad message.
            if (status != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.authority.positive", set));
                return;
            }

            if (wcs.size() > 0) {
                if (set.getType() == Type.NSEC) {
                    if (nsecs == null) {
                        nsecs = new ArrayList<NSECRecord>();
                    }

                    nsecs.add((NSECRecord)set.first());
                }
                else if (set.getType() == Type.NSEC3) {
                    if (nsec3s == null) {
                        nsec3s = new ArrayList<NSEC3Record>();
                    }

                    nsec3s.add((NSEC3Record)set.first());
                }
            }
        }

        // If this is a positive wildcard response, and we have NSEC records,
        // try to use them to
        // 1) prove that qname doesn't exist and
        // 2) that the correct wildcard was used.
        if (wcs.size() > 0) {
            for (Map.Entry<Name, Name> wc : wcs.entrySet()) {
                boolean wcNsecOk = false;
                if (nsecs != null) {
                    for (NSECRecord nsec : nsecs) {
                        if (ValUtils.nsecProvesNameError(nsec, wc.getKey())) {
                            try {
                                Name nsecWc = ValUtils.nsecWildcard(wc.getKey(), nsec);
                                if (wc.getValue().equals(nsecWc)) {
                                    wcNsecOk = true;
                                    break;
                                }
                            }
                            catch (NameTooLongException e) {
                                response.setBogus(R.get("failed.positive.wildcardgeneration"));
                                logger.error("Could not generate NSEC wildcard", e);
                                return;
                            }
                        }
                    }
                }

                // If this was a positive wildcard response that we haven't
                // already proven, and we have NSEC3 records, try to prove it
                // using the NSEC3 records.
                if (!wcNsecOk && nsec3s != null) {
                    if (this.n3valUtils.proveWildcard(nsec3s, wc.getKey(), keyRrset.getName(), wc.getValue())) {
                        wcNsecOk = true;
                    }
                }

                // If after all this, we still haven't proven the positive
                // wildcard
                // response, fail.
                if (!wcNsecOk) {
                    response.setBogus(R.get("failed.positive.wildcard_too_broad"));
                    return;
                }
            }
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
     * @param request The request that generated this response.
     * @param response The response to validate.
     */
    private void validateAnyResponse(Message request, SMessage response) {
        int qtype = request.getQuestion().getType();

        if (qtype != Type.ANY) {
            throw new IllegalArgumentException("ANY validation called on non-ANY response.");
        }

        SMessage m = response;

        // validate the ANSWER section.
        for (SRRset set : response.getSectionRRsets(Section.ANSWER)) {
            KeyEntry ke = this.prepareFindKey(set, request);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, ke.getRRset());
            // If the (answer) rrset failed to validate, then this message is
            // BAD.
            if (status != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.answer.positive"));
                return;
            }
        }

        // validate the AUTHORITY section as well - this will be the NS rrset
        // (which could be missing, no problem)
        for (SRRset set : m.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, request);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, ke.getRRset());
            // If anything in the authority section fails to be secure, we have
            // a bad message.
            if (status != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.authority.positive"));
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
     * @param request The request that generated this response.
     * @param response The response to validate.
     */
    private void validateNodataResponse(Message request, SMessage response) {
        Name qname = request.getQuestion().getName();
        int qtype = request.getQuestion().getType();

        // Since we are here, the ANSWER section is either empty (and hence
        // there's only the NODATA to validate) OR it contains an incomplete
        // chain. In this case, the records were already validated before and we
        // can concentrate on following the qname that lead to the NODATA
        // classification
        for (SRRset set : response.getSectionRRsets(Section.ANSWER)) {
            if (set.getSecurityStatus() != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.answer.cname_nodata", set.getName()));
                return;
            }

            if (set.getType() == Type.CNAME) {
                qname = ((CNAMERecord)set.first()).getTarget();
            }
        }

        // If true, then the NODATA has been proven.
        boolean hasValidNSEC = false;

        // for wildcard nodata responses. This is the proven closest encloser.
        Name ce = null;

        // for wildcard nodata responses. This is the wildcard NSEC.
        Name wc = null;

        // A collection of NSEC3 RRs found in the authority section.
        List<NSEC3Record> nsec3s = null;

        // The RRSIG signer field for the NSEC3 RRs.
        Name nsec3Signer = null;

        // validate the AUTHORITY section
        for (SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
            KeyEntry ke = this.prepareFindKey(set, request);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            SecurityStatus status = this.valUtils.verifySRRset(set, ke.getRRset());
            if (status != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.authority.nodata", set));
                return;
            }

            // If we encounter an NSEC record, try to use it to prove NODATA.
            // This needs to handle the empty non-terminal (ENT) NODATA case.
            if (set.getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord)set.first();
                if (ValUtils.nsecProvesNodata(nsec, qname, qtype)) {
                    hasValidNSEC = true;
                    if (nsec.getName().isWild()) {
                        wc = new Name(nsec.getName(), 1);
                    }
                }

                if (ValUtils.nsecProvesNameError(nsec, qname)) {
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
        if (wc != null && (ce == null || (!ce.equals(wc) && !qname.equals(ce)))) {
            hasValidNSEC = false;
        }

        this.n3valUtils.stripUnknownAlgNSEC3s(nsec3s);
        if (!hasValidNSEC && nsec3s != null && nsec3s.size() > 0) {
            // try to prove NODATA with our NSEC3 record(s)
            SecurityStatus status = this.n3valUtils.proveNodata(nsec3s, qname, qtype, nsec3Signer);
            if (status == SecurityStatus.INSECURE) {
                response.setStatus(SecurityStatus.INSECURE);
                return;
            }

            hasValidNSEC = status == SecurityStatus.SECURE;
        }

        if (!hasValidNSEC) {
            response.setBogus(R.get("failed.nodata"));
            logger.trace("Failed NODATA for " + qname);
            return;
        }

        logger.trace("sucessfully validated NODATA response.");
        response.setStatus(SecurityStatus.SECURE);
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
     * @param request The request to be proved to not exist.
     * @param response The response to validate.
     */
    private void validateNameErrorResponse(Message request, SMessage response) {
        Name qname = request.getQuestion().getName();

        // The ANSWER section is either empty OR it contains an xNAME chain that
        // ultimately lead to the NAMEERROR response. In this case the ANSWER
        // section has already been validated before and we can concentrate on
        // following the xNAMEs to find the qname that caused the NXDOMAIN.
        for (SRRset set : response.getSectionRRsets(Section.ANSWER)) {
            if (set.getSecurityStatus() != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.nxdomain.cname_nxdomain", set));
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
            KeyEntry ke = this.prepareFindKey(set, request);
            if (!this.processKeyValidate(response, set.getSignerName(), ke)) {
                return;
            }

            keyRrset = ke.getRRset();
            SecurityStatus status = this.valUtils.verifySRRset(set, keyRrset);
            if (status != SecurityStatus.SECURE) {
                response.setBogus(R.get("failed.nxdomain.authority", set));
                return;
            }

            if (set.getType() == Type.NSEC) {
                NSECRecord nsec = (NSECRecord)set.first();
                if (ValUtils.nsecProvesNameError(nsec, qname)) {
                    hasValidNSEC = true;
                }

                if (ValUtils.nsecProvesNoWC(nsec, qname)) {
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

        this.n3valUtils.stripUnknownAlgNSEC3s(nsec3s);
        if ((!hasValidNSEC || !hasValidWCNSEC) && nsec3s != null) {
            logger.debug("Validating nxdomain: using NSEC3 records");

            // Attempt to prove name error with nsec3 records.
            if (this.n3valUtils.allNSEC3sIgnoreable(nsec3s, keyRrset)) {
                response.setStatus(SecurityStatus.INSECURE, R.get("failed.nxdomain.nsec3_ignored"));
                return;
            }

            SecurityStatus status = this.n3valUtils.proveNameError(nsec3s, qname, nsec3Signer);
            if (status != SecurityStatus.SECURE) {
                if (status == SecurityStatus.BOGUS) {
                    response.setStatus(status, R.get("failed.nxdomain.nsec3_bogus"));
                }
                else if (status == SecurityStatus.INSECURE) {
                    response.setStatus(status, R.get("failed.nxdomain.nsec3_insecure"));
                }

                return;
            }

            // Note that we assume that the NSEC3ValUtils proofs encompass the
            // wildcard part of the proof.
            hasValidNSEC = true;
            hasValidWCNSEC = true;
        }

        // If the message fails to prove either condition, it is bogus.
        if (!hasValidNSEC) {
            response.setBogus(R.get("failed.nxdomain.exists", response.getQuestion().getName()));
            return;
        }

        if (!hasValidWCNSEC) {
            response.setBogus(R.get("failed.nxdomain.haswildcard"));
            return;
        }

        // Otherwise, we consider the message secure.
        logger.trace("successfully validated NAME ERROR response.");
        response.setStatus(SecurityStatus.SECURE);
    }

    private SMessage sendRequest(Message request) {
        Record q = request.getQuestion();
        logger.trace("sending request: <" + q.getName() + "/" + Type.string(q.getType()) + "/" + DClass.string(q.getDClass()) + ">");

        // Send the request along by using a local copy of the request
        Message localRequest = (Message)request.clone();
        localRequest.getHeader().setFlag(Flags.CD);
        try {
            Message resp = this.headResolver.send(localRequest);
            return new SMessage(resp);
        }
        catch (SocketTimeoutException e) {
            logger.error("Query timed out, returning fail", e);
            return ValidatingResolver.errorMessage(localRequest, Rcode.SERVFAIL);
        }
        catch (UnknownHostException e) {
            logger.error("failed to send query", e);
            return ValidatingResolver.errorMessage(localRequest, Rcode.SERVFAIL);
        }
        catch (IOException e) {
            logger.error("failed to send query", e);
            return ValidatingResolver.errorMessage(localRequest, Rcode.SERVFAIL);
        }
    }

    private KeyEntry prepareFindKey(SRRset rrset, Message request) {
        FindKeyState state = new FindKeyState();
        state.signerName = rrset.getSignerName();
        state.qclass = request.getQuestion().getDClass();

        if (state.signerName == null) {
            int qtype = request.getQuestion().getType();
            if (qtype == Type.DS || qtype == Type.NS) {
                state.signerName = new Name(request.getQuestion().getName(), 1);
            }
            else {
                state.signerName = request.getQuestion().getName();
            }
        }

        SRRset trustAnchorRRset = this.trustAnchors.find(state.signerName, rrset.getDClass());
        if (trustAnchorRRset == null) {
            // response isn't under a trust anchor, so we cannot validate.
            return KeyEntry.newNullKeyEntry(rrset.getSignerName(), rrset.getDClass(), DEFAULT_TA_BAD_KEY_TTL);
        }

        state.keyEntry = this.keyCache.find(state.signerName, rrset.getDClass());
        if (state.keyEntry == null || (!state.keyEntry.getName().equals(state.signerName) && state.keyEntry.isGood())) {
            // start the FINDKEY phase with the trust anchor
            state.dsRRset = trustAnchorRRset;
            state.keyEntry = null;
            state.currentDSKeyName = new Name(trustAnchorRRset.getName(), 1);

            // and otherwise, don't continue processing this event.
            // (it will be reactivated when the priming query returns).
            processFindKey(state);
        }

        return state.keyEntry;
    }

    /**
     * Process the FINDKEY state. Generally this just calculates the next name
     * to query and either issues a DS or a DNSKEY query. It will check to see
     * if the correct key has already been reached, in which case it will
     * advance the event to the next state.
     * 
     * @param state The state associated with the current key finding phase.
     */
    private void processFindKey(FindKeyState state) {
        // We know that state.keyEntry is not a null or bad key -- if it were,
        // then previous processing should have directed this event to a
        // different state.
        int qclass = state.qclass;
        Name targetKeyName = state.signerName;
        Name currentKeyName = Name.empty;
        if (state.keyEntry != null) {
            currentKeyName = state.keyEntry.getName();
        }
        else {
            currentKeyName = state.currentDSKeyName;
            state.currentDSKeyName = null;
        }

        // If our current key entry matches our target, then we are done.
        if (currentKeyName.equals(targetKeyName)) {
            return;
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
            return;
        }

        Name nextKeyName = new Name(targetKeyName, l);
        logger.trace("findKey: targetKeyName = " + targetKeyName + ", currentKeyName = " + currentKeyName + ", nextKeyName = " + nextKeyName);

        // The next step is either to query for the next DS, or to query for the
        // next DNSKEY.
        if (state.dsRRset == null || !state.dsRRset.getName().equals(nextKeyName)) {
            Message dsRequest = Message.newQuery(Record.newRecord(nextKeyName, Type.DS, qclass));
            SMessage dsResponse = this.sendRequest(dsRequest);
            this.processDSResponse(dsRequest, dsResponse, state);
            return;
        }

        // Otherwise, it is time to query for the DNSKEY
        Message dnskeyRequest = Message.newQuery(Record.newRecord(state.dsRRset.getName(), Type.DNSKEY, qclass));
        SMessage dnskeyResponse = this.sendRequest(dnskeyRequest);
        this.processDNSKEYResponse(dnskeyRequest, dnskeyResponse, state);
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
                    bogusKE.setBadReason(R.get("failed.ds"));
                    return bogusKE;
                }

                if (!ValUtils.atLeastOneSupportedAlgorithm(dsRrset)) {
                    KeyEntry nullKey = KeyEntry.newNullKeyEntry(qname, qclass, dsRrset.getTTL());
                    nullKey.setBadReason(R.get("insecure.ds.noalgorithms", qname));
                    return nullKey;
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
                    bogusKE.setBadReason(R.get("failed.ds.cname"));
                    return bogusKE;
                }

                // Otherwise, we return the positive response.
                logger.trace("CNAME rrset was good, unsigned response.");
                return KeyEntry.newNullKeyEntry(cnameRrset.getName(), qclass, DEFAULT_TA_BAD_KEY_TTL);

            case NODATA:
            case NAMEERROR:
                return this.dsReponseToKeForNodata(response, request, keyRrset);

            default:
                // We've encountered an unhandled classification for this
                // response.
                bogusKE.setBadReason(R.get("failed.ds.notype", subtype));
                return bogusKE;
        }
    }

    /**
     * Given a DS response, the DS request, and the current key rrset, validate
     * the DS response for the NODATA case, returning a KeyEntry.
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
    private KeyEntry dsReponseToKeForNodata(SMessage response, Message request, SRRset keyRrset) {
        Name qname = request.getQuestion().getName();
        int qclass = request.getQuestion().getDClass();
        KeyEntry bogusKE = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);

        SecurityStatus status;
        // NODATA means that the qname exists, but that there was no DS.
        // This is a pretty normal case. NAMEERROR shouldn't happen, but
        // can be proven.
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
                bogusKE.setBadReason(R.get("failed.ds.nsec"));
                return bogusKE;
            }

            NSECRecord nsec = (NSECRecord)nsecRrset.first();
            switch (ValUtils.nsecProvesNoDS(nsec, qname)) {
                case BOGUS: // something was wrong.
                    bogusKE.setBadReason(R.get("failed.ds.nsec.hasdata"));
                    return bogusKE;
                case INSECURE: // this wasn't a delegation point.
                    logger.debug("NSEC RRset for the referral proved not a delegation point");
                    return null;
                case SECURE: // this proved no DS.
                    KeyEntry nullKey = KeyEntry.newNullKeyEntry(qname, qclass, nsecRrset.getTTL());
                    nullKey.setBadReason(R.get("insecure.ds.nsec"));
                    return nullKey;
                default:
                    throw new RuntimeException("unexpected security status");
            }
        }

        // Otherwise, there is no NSEC at qname. This could be an ENT.
        // If not, this is broken.
        for (SRRset set : response.getSectionRRsets(Section.AUTHORITY, Type.NSEC)) {
            status = this.valUtils.verifySRRset(set, keyRrset);
            if (status != SecurityStatus.SECURE) {
                bogusKE.setBadReason(R.get("failed.ds.nsec.ent"));
                return bogusKE;
            }

            NSECRecord nsec = (NSECRecord)set.first();
            if (ValUtils.nsecProvesNodata(nsec, qname, Type.DS)) {
                KeyEntry nullKey = KeyEntry.newNullKeyEntry(qname, qclass, set.getTTL());
                nullKey.setBadReason(R.get("insecure.ds.nsec.ent"));
                return nullKey;
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

            switch (this.n3valUtils.proveNoDS(nsec3s, qname, nsec3Signer)) {
                case BOGUS:
                    bogusKE.setBadReason(R.get("failed.ds.nsec3"));
                    return bogusKE;
                case INSECURE:
                    logger.debug("nsec3s proved no delegation.");
                    return null;
                case SECURE:
                    KeyEntry nullKey = KeyEntry.newNullKeyEntry(qname, qclass, nsec3TTL);
                    nullKey.setBadReason(R.get("insecure.ds.nsec3"));
                    return nullKey;
                default:
                    throw new RuntimeException("unexpected security status");
            }
        }

        // Apparently, no available NSEC/NSEC3 proved NODATA, so this is
        // BOGUS.
        bogusKE.setBadReason(R.get("failed.ds.unknown"));
        return bogusKE;
    }

    /**
     * This handles the responses to locally generated DS queries.
     * 
     * @param request The request for which the response is processed.
     * @param response The response to process.
     * @param state The state associated with the current key finding phase.
     */
    private void processDSResponse(Message request, SMessage response, FindKeyState state) {
        Name qname = request.getQuestion().getName();

        state.emptyDSName = null;
        state.dsRRset = null;

        KeyEntry dsKE = this.dsResponseToKE(response, request, state.keyEntry.getRRset());
        if (dsKE == null) {
            // DS response indicated that we aren't on a delegation point.
            state.emptyDSName = qname;
        }
        else if (dsKE.isGood()) {
            state.dsRRset = dsKE.getRRset();
        }
        else {
            // The reason for the DS to be not good (that is, either bad
            // or null) should have been logged by dsResponseToKE.
            state.keyEntry = dsKE;
            if (dsKE.isNull()) {
                this.keyCache.store(dsKE);
            }

            // The FINDKEY phase has ended, so move on.
            return;
        }

        this.processFindKey(state);
    }

    private void processDNSKEYResponse(Message request, SMessage response, FindKeyState state) {
        Name qname = request.getQuestion().getName();
        int qclass = request.getQuestion().getDClass();

        SRRset dnskeyRrset = response.findAnswerRRset(qname, Type.DNSKEY, qclass);
        if (dnskeyRrset == null) {
            // If the DNSKEY rrset was missing, this is the end of the line.
            state.keyEntry = KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
            state.keyEntry.setBadReason(R.get("dnskey.no_rrset", qname));
            return;
        }

        state.keyEntry = this.valUtils.verifyNewDNSKEYs(dnskeyRrset, state.dsRRset, DEFAULT_TA_BAD_KEY_TTL);

        // If the key entry isBad or isNull, then we can move on to the next
        // state.
        if (!state.keyEntry.isGood()) {
            return;
        }

        // The DNSKEY validated, so cache it as a trusted key rrset.
        this.keyCache.store(state.keyEntry);

        // If good, we stay in the FINDKEY state.
        this.processFindKey(state);
    }

    private boolean processKeyValidate(SMessage response, Name signerName, KeyEntry keyEntry) {
        // signerName being null is the indicator that this response was
        // unsigned
        if (signerName == null) {
            logger.debug("processKeyValidate: no signerName.");
            // Unsigned responses must be underneath a "null" key entry.
            if (keyEntry.isNull()) {
                response.setStatus(SecurityStatus.INSECURE, R.get("validate.insecure_unsigned"));
                return false;
            }

            if (keyEntry.isGood()) {
                response.setStatus(SecurityStatus.BOGUS, R.get("validate.bogus.missingsig"));
                return false;
            }

            response.setStatus(SecurityStatus.BOGUS, R.get("validate.bogus", keyEntry.getBadReason()));
            return false;
        }

        if (keyEntry.isBad()) {
            response.setStatus(SecurityStatus.BOGUS, R.get("validate.bogus.badkey", keyEntry.getName(), keyEntry.getBadReason()));
            return false;
        }

        if (keyEntry.isNull()) {
            response.setStatus(SecurityStatus.INSECURE, R.get("validate.insecure"));
            return false;
        }

        return true;
    }

    private SMessage processValidate(Message request, SMessage response) {
        ResponseClassification subtype = ValUtils.classifyResponse(response);
        switch (subtype) {
            case POSITIVE:
            case CNAME:
                logger.trace("Validating a positive response");
                this.validatePositiveResponse(request, response);
                break;

            case NODATA:
                logger.trace("Validating a nodata response");
                this.validateNodataResponse(request, response);
                break;

            case CNAME_NODATA:
                logger.trace("Validating a CNAME_NODATA response");
                this.validatePositiveResponse(request, response);
                if (response.getStatus() != SecurityStatus.INSECURE) {
                    response.setStatus(SecurityStatus.UNCHECKED);
                    this.validateNodataResponse(request, response);
                }

                break;

            case NAMEERROR:
                logger.trace("Validating a nxdomain response");
                this.validateNameErrorResponse(request, response);
                break;

            case CNAME_NAMEERROR:
                logger.trace("Validating a cname_nxdomain response");
                this.validatePositiveResponse(request, response);
                if (response.getStatus() != SecurityStatus.INSECURE) {
                    response.setStatus(SecurityStatus.UNCHECKED);
                    this.validateNameErrorResponse(request, response);
                }

                break;

            case ANY:
                logger.trace("Validating a postive ANY response");
                this.validateAnyResponse(request, response);
                break;

            default:
                response.setStatus(SecurityStatus.BOGUS, R.get("validate.response.unknown", subtype));
        }

        return this.processFinishedState(request, response);
    }

    /**
     * Apply any final massaging to a response before returning up the pipeline.
     * Primarily this means setting the AD bit or not and possibly stripping
     * DNSSEC data.
     */
    private SMessage processFinishedState(Message request, SMessage response) {
        // If the response message validated, set the AD bit.
        SecurityStatus status = response.getStatus();
        String reason = response.getBogusReason();
        switch (status) {
            case BOGUS:
                // For now, in the absence of any other API information, we
                // return SERVFAIL.
                int code = response.getHeader().getRcode();
                if (code == Rcode.NOERROR || code == Rcode.NXDOMAIN) {
                    code = Rcode.SERVFAIL;
                }

                response = ValidatingResolver.errorMessage(request, code);
                break;
            case SECURE:
                response.getHeader().setFlag(Flags.AD);
                break;
            case UNCHECKED:
            case INSECURE:
                break;
            default:
                throw new RuntimeException("unexpected security status");
        }

        response.setStatus(status, reason);
        return response;
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
        SMessage response = this.sendRequest(query);

        // If the CD bit is set, do not process the (cached) validation status.
        if (query.getHeader().getFlag(Flags.CD)) {
            return response.getMessage();
        }

        // Positive RRSIG responses cannot be validated as there are no
        // signatures on signatures. Negative answers CAN be validated.
        Message rrsigResponse = response.getMessage();
        if (query.getQuestion().getType() == Type.RRSIG && query.getHeader().getRcode() == Rcode.NOERROR
                && rrsigResponse.getSectionRRsets(Section.ANSWER).length > 0) {
            rrsigResponse.getHeader().unsetFlag(Flags.AD);
            return rrsigResponse;
        }

        final SMessage validated = this.processValidate(query, response);

        Message m = validated.getMessage();
        if (validated.getBogusReason() != null) {
            m.addRecord(new TXTRecord(Name.root, VALIDATION_REASON_QCLASS, 0, Arrays.asList(validated.getBogusReason().split("(?<=\\G.{255})"))),
                    Section.ADDITIONAL);
        }

        return m;
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

    /**
     * Creates a response message with the given return code.
     * 
     * @param request The request for which the response belongs.
     * @param rcode The response code, @see Rcode
     * @return The response message for <code>request</code>.
     */
    private static SMessage errorMessage(Message request, int rcode) {
        SMessage m = new SMessage(request.getHeader().getID(), request.getQuestion());
        Header h = m.getHeader();
        h.setRcode(rcode);
        h.setFlag(Flags.QR);

        return m;
    }
}
