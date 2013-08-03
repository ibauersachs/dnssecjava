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

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import org.apache.log4j.Logger;
import org.jitsi.dnssec.SecurityStatus;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC.Algorithm;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSEC3Record.Flags;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.RRset;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.utils.base32;

/**
 * NSEC3 non-existence proof utilities.
 */
final class NSEC3ValUtils {
    // FIXME: should probably refactor to handle different NSEC3 parameters more
    // efficiently.
    // Given a list of NSEC3 RRs, they should be grouped according to
    // parameters. The idea is to hash and compare for each group independently,
    // instead of having to skip NSEC3 RRs with the wrong parameters.

    // The logger to use in static methods.
    private static final Logger logger = Logger.getLogger(NSEC3ValUtils.class);

    private static final Name ASTERISK_LABEL = Name.fromConstantString("*");

    private static final int MAX_ITERATION_COUNT = 65536;

    private TreeMap<Integer, Integer> maxIterations;

    /**
     * Creates a new instance of this class.
     */
    NSEC3ValUtils() {
        // see RFC5155#10.3 for the max iteration count
        // CHECKSTYLE:OFF
        this.maxIterations = new TreeMap<Integer, Integer>();
        this.maxIterations.put(1024, 150);
        this.maxIterations.put(2048, 500);
        this.maxIterations.put(4096, 2500);
        // CHECKSTYLE:ON
    }

    /**
     * Loads the configuration data. Supported properties are:
     * <ul>
     * <li>org.jitsi.dnssec.nsec3.iterations.M=N</li>
     * </ul>
     * 
     * @param config The configuration data.
     */
    void init(Properties config) {
        boolean first = true;
        for (Map.Entry<?, ?> s : config.entrySet()) {
            String key = s.getKey().toString();
            if (key.startsWith("org.jitsi.dnssec.nsec3.iterations")) {
                int keySize = Integer.parseInt(key.substring(key.lastIndexOf(".") + 1));
                int iters = Integer.parseInt(s.getValue().toString());
                if (iters > MAX_ITERATION_COUNT) {
                    throw new IllegalArgumentException("Iteration count too high.");
                }

                if (first) {
                    first = false;
                    this.maxIterations.clear();
                }

                this.maxIterations.put(keySize, iters);
            }
        }
    }

    /**
     * This is a class to encapsulate a unique set of NSEC3 parameters:
     * algorithm, iterations, and salt.
     */
    private static class NSEC3Parameters {
        private int alg;
        private byte[] salt;
        private int iterations;

        public NSEC3Parameters(NSEC3Record r) {
            this.alg = r.getHashAlgorithm();
            this.salt = r.getSalt();
            this.iterations = r.getIterations();
        }

        public boolean match(NSEC3Record r) {
            if (r.getHashAlgorithm() != this.alg) {
                return false;
            }

            if (r.getIterations() != this.iterations) {
                return false;
            }

            if (this.salt == null && r.getSalt() != null) {
                return false;
            }

            return Arrays.equals(r.getSalt(), this.salt);
        }
    }

    /**
     * This is just a simple class to encapsulate the response to a closest
     * encloser proof.
     */
    private final class CEResponse {
        private Name closestEncloser;
        private NSEC3Record ceNsec3;
        private NSEC3Record ncNsec3;

        /**
         * <ul>
         * <li>bogus if no closest encloser could be proven.</li>
         * <li>secure if a closest encloser could be proven, ce is set.</li>
         * <li>insecure if the closest-encloser candidate turns out to prove
         * that an insecure delegation exists above the qname.</li>
         * </ul>
         */
        private SecurityStatus status = SecurityStatus.UNCHECKED;

        private CEResponse(Name ce, NSEC3Record nsec3) {
            this.closestEncloser = ce;
            this.ceNsec3 = nsec3;
        }
    }

    private boolean supportsHashAlgorithm(int alg) {
        if (alg == NSEC3Record.SHA1_DIGEST_ID) {
            return true;
        }

        return false;
    }

    /**
     * Remove all records whose algorithm is unknown.
     * 
     * @param nsec3s List of NSEC3 records to check. The list is modified by
     *            this method.
     */
    public void stripUnknownAlgNSEC3s(List<NSEC3Record> nsec3s) {
        if (nsec3s == null) {
            return;
        }

        for (ListIterator<NSEC3Record> i = nsec3s.listIterator(); i.hasNext();) {
            NSEC3Record nsec3 = i.next();
            if (!this.supportsHashAlgorithm(nsec3.getHashAlgorithm())) {
                i.remove();
            }
        }
    }

    /**
     * Given a list of NSEC3Records that are part of a message, determine the
     * NSEC3 parameters (hash algorithm, iterations, and salt) present. If there
     * is more than one distinct grouping, return null;
     * 
     * @param nsec3s A list of NSEC3Record object.
     * @return A set containing a number of objects (NSEC3Parameter objects)
     *         that correspond to each distinct set of parameters, or null if
     *         the nsec3s list was empty.
     */
    public NSEC3Parameters nsec3Parameters(List<NSEC3Record> nsec3s) {
        if (nsec3s == null || nsec3s.size() == 0) {
            return null;
        }

        NSEC3Parameters params = new NSEC3Parameters((NSEC3Record)nsec3s.get(0));
        for (NSEC3Record nsec3 : nsec3s) {
            if (!params.match(nsec3)) {
                return null;
            }
        }

        return params;
    }

    /**
     * Given a hash and an a zone name, construct an NSEC3 ownername.
     * 
     * @param hash The hash of an original name.
     * @param zonename The zone to use in constructing the NSEC3 name.
     * @return The NSEC3 name.
     */
    private Name hashName(byte[] hash, Name zonename) {
        try {
            return new Name(new base32(base32.Alphabet.BASE32HEX, false, false).toString(hash), zonename);
        }
        catch (TextParseException e) {
            // Note, this should never happen.
            return null;
        }
    }

    /**
     * Given a set of NSEC3 parameters, hash a name.
     * 
     * @param name The name to hash.
     * @param params The parameters to hash with.
     * @return The hash.
     */
    private byte[] hash(Name name, NSEC3Parameters params) {
        try {
            int[] types = new int[] { Type.A };
            NSEC3Record r = new NSEC3Record(name, DClass.IN, (long)0, params.alg, 0, params.iterations, params.salt, new byte[0], types);
            return r.hashName(name);
        }
        catch (NoSuchAlgorithmException e) {
            logger.debug("Did not recognize hash algorithm: " + params.alg);
            return null;
        }
    }

    /**
     * Given the name of a closest encloser, return the name *.closest_encloser.
     * 
     * @param closestEncloser The name to start with.
     * @return The wildcard name.
     */
    private Name ceWildcard(Name closestEncloser) {
        try {
            return Name.concatenate(ASTERISK_LABEL, closestEncloser);
        }
        catch (NameTooLongException e) {
            return null;
        }
    }

    /**
     * Given a qname and its proven closest encloser, calculate the "next
     * closest" name. Basically, this is the name that is one label longer than
     * the closest encloser that is still a subdomain of qname.
     * 
     * @param qname The qname.
     * @param closestEncloser The closest encloser name.
     * @return The next closer name.
     */
    private Name nextClosest(Name qname, Name closestEncloser) {
        int strip = qname.labels() - closestEncloser.labels() - 1;
        return (strip > 0) ? new Name(qname, strip) : qname;
    }

    /**
     * Find the NSEC3Record that matches a hash of a name.
     * 
     * @param hash The pre-calculated hash of a name.
     * @param zonename The name of the zone that the NSEC3s are from.
     * @param nsec3s A list of NSEC3Records from a given message.
     * @param params The parameters used for calculating the hash.
     * 
     * @return The matching NSEC3Record, if one is present.
     */
    private NSEC3Record findMatchingNSEC3(byte[] hash, Name zonename, List<NSEC3Record> nsec3s, NSEC3Parameters params) {
        Name n = this.hashName(hash, zonename);

        for (NSEC3Record nsec3 : nsec3s) {
            // Skip nsec3 records that are using different parameters.
            if (!params.match(nsec3)) {
                continue;
            }

            if (n.equals(nsec3.getName())) {
                return nsec3;
            }
        }

        return null;
    }

    /**
     * Given a hash and a candidate NSEC3Record, determine if that NSEC3Record
     * covers the hash. Covers specifically means that the hash is in between
     * the owner and next hashes and does not equal either.
     * 
     * @param nsec3 The candidate NSEC3Record.
     * @param hash The precalculated hash.
     * @return True if the NSEC3Record covers the hash.
     */
    private boolean nsec3Covers(NSEC3Record nsec3, byte[] hash) {
        byte[] owner = new base32(base32.Alphabet.BASE32HEX, false, false).fromString(nsec3.getName().getLabelString(0));
        byte[] next = nsec3.getNext();

        // This is the "normal case: owner < next and owner < hash < next
        ByteArrayComparator bac = new ByteArrayComparator();
        if (bac.compare(owner, hash) < 0 && bac.compare(hash, next) < 0) {
            return true;
        }

        // this is the end of zone case:
        // next <= owner && (hash > owner || hash < next)
        if (bac.compare(next, owner) <= 0 && (bac.compare(hash, owner) > 0 || bac.compare(hash, next) < 0)) {
            return true;
        }

        // Otherwise, the NSEC3 does not cover the hash.
        return false;
    }

    /**
     * Given a pre-hashed name, find a covering NSEC3 from among a list of
     * NSEC3s.
     * 
     * @param hash The hash to consider.
     * @param zonename The name of the zone.
     * @param nsec3s The list of NSEC3s present in a message.
     * @param params The NSEC3 parameters used to generate the hash -- NSEC3s
     *            that do not use those parameters will be skipped.
     * 
     * @return A covering NSEC3 if one is present, null otherwise.
     */
    private NSEC3Record findCoveringNSEC3(byte[] hash, Name zonename, List<NSEC3Record> nsec3s, NSEC3Parameters params) {
        for (NSEC3Record nsec3 : nsec3s) {
            if (!params.match(nsec3)) {
                continue;
            }

            if (this.nsec3Covers(nsec3, hash)) {
                return nsec3;
            }
        }

        return null;
    }

    /**
     * Given a name and a list of NSEC3s, find the candidate closest encloser.
     * This will be the first ancestor of 'name' (including itself) to have a
     * matching NSEC3 RR.
     * 
     * @param name The name the start with.
     * @param zonename The name of the zone that the NSEC3s came from.
     * @param nsec3s The list of NSEC3s.
     * @param params The NSEC3 parameters.
     * 
     * @return A CEResponse containing the closest encloser name and the NSEC3
     *         RR that matched it, or null if there wasn't one.
     */
    private CEResponse findClosestEncloser(Name name, Name zonename, List<NSEC3Record> nsec3s, NSEC3Parameters params) {
        // This scans from longest name to shortest, so the first match we find
        // is the only viable candidate.
        // FIXME: modify so that the NSEC3 matching the zone apex need not be
        // present.
        while (name.labels() >= zonename.labels()) {
            NSEC3Record nsec3 = this.findMatchingNSEC3(this.hash(name, params), zonename, nsec3s, params);
            if (nsec3 != null) {
                return new CEResponse(name, nsec3);
            }

            name = new Name(name, 1);
        }

        return null;
    }

    /**
     * Given a List of nsec3 RRs, find and prove the closest encloser to qname.
     * 
     * @param qname The qname in question.
     * @param zonename The name of the zone that the NSEC3 RRs come from.
     * @param nsec3s The list of NSEC3s found the this response (already
     *            verified).
     * @param params The NSEC3 parameters found in the response.
     * @return null if the proof isn't completed. Otherwise, return a CEResponse
     *         object which contains the closest encloser name and the NSEC3
     *         that matches it.
     */
    private CEResponse proveClosestEncloser(Name qname, Name zonename, List<NSEC3Record> nsec3s, NSEC3Parameters params) {
        CEResponse candidate = this.findClosestEncloser(qname, zonename, nsec3s, params);

        if (candidate == null) {
            logger.debug("proveClosestEncloser: could not find a candidate for the closest encloser.");
            candidate = new CEResponse(Name.empty, null);
            candidate.status = SecurityStatus.BOGUS;
            return candidate;
        }

        if (candidate.closestEncloser.equals(qname)) {
            logger.debug("proveClosestEncloser: proved that qname existed!");
            candidate.status = SecurityStatus.BOGUS;
            return candidate;
        }

        // If the closest encloser is actually a delegation, then the response
        // should have been a referral. If it is a DNAME, then it should have
        // been a DNAME response.
        if (candidate.ceNsec3.hasType(Type.NS) && !candidate.ceNsec3.hasType(Type.SOA)) {
            if (!candidate.ceNsec3.hasType(Type.DS)) {
                candidate.status = SecurityStatus.INSECURE;
                return candidate;
            }

            logger.debug("proveClosestEncloser: closest encloser was a delegation!");
            candidate.status = SecurityStatus.BOGUS;
            return candidate;
        }

        if (candidate.ceNsec3.hasType(Type.DNAME)) {
            logger.debug("proveClosestEncloser: closest encloser was a DNAME!");
            candidate.status = SecurityStatus.BOGUS;
            return candidate;
        }

        // Otherwise, we need to show that the next closer name is covered.
        Name nextClosest = nextClosest(qname, candidate.closestEncloser);
        byte[] ncHash = this.hash(nextClosest, params);
        candidate.ncNsec3 = this.findCoveringNSEC3(ncHash, zonename, nsec3s, params);
        if (candidate.ncNsec3 == null) {
            logger.debug("Could not find proof that the closest encloser was the closest encloser");
            candidate.status = SecurityStatus.BOGUS;
            return candidate;
        }

        candidate.status = SecurityStatus.SECURE;
        return candidate;
    }

    private boolean validIterations(NSEC3Parameters nsec3params, RRset dnskeyRrset) {
        // for now, we return the maximum iterations based simply on the key
        // algorithms that may have been used to sign the NSEC3 RRsets.
        try {
            for (Iterator<?> i = dnskeyRrset.rrs(); i.hasNext();) {
                DNSKEYRecord dnskey = (DNSKEYRecord)i.next();
                int keysize = 0;
                switch (dnskey.getAlgorithm()) {
                    case Algorithm.RSAMD5:
                        return false; // obsoleted by rfc6944
                    case Algorithm.RSASHA1:
                    case Algorithm.RSASHA256:
                    case Algorithm.RSASHA512:
                    case Algorithm.RSA_NSEC3_SHA1:
                        keysize = ((RSAPublicKey)dnskey.getPublicKey()).getModulus().bitLength();
                        break;
                    case Algorithm.DSA:
                    case Algorithm.DSA_NSEC3_SHA1:
                        keysize = ((DSAPublicKey)dnskey.getPublicKey()).getParams().getP().bitLength();
                        break;
                    case Algorithm.ECDSAP256SHA256:
                    case Algorithm.ECDSAP384SHA384:
                        keysize = ((ECPublicKey)dnskey.getPublicKey()).getParams().getCurve().getField().getFieldSize();
                        break;
                    default:
                        return false;
                }

                Integer keyIters = this.maxIterations.floorKey(keysize);
                if (keyIters == null) {
                    keyIters = this.maxIterations.firstKey();
                }

                if (nsec3params.iterations > keyIters) {
                    return false;
                }
            }

            return true;
        }
        catch (DNSSECException e) {
            logger.error("Could not get public key from NSEC3 record", e);
            return false;
        }
    }

    /**
     * Determine if all of the NSEC3s in a response are legally ignoreable
     * (i.e., their presence should lead to an INSECURE result). Currently, this
     * is solely based on iterations.
     * 
     * @param nsec3s The list of NSEC3s. If there is more than one set of NSEC3
     *            parameters present, this test will not be performed.
     * @param dnskeyRrset The set of validating DNSKEYs.
     * @return true if all of the NSEC3s can be legally ignored, false if not.
     */
    public boolean allNSEC3sIgnoreable(List<NSEC3Record> nsec3s, RRset dnskeyRrset) {
        NSEC3Parameters params = this.nsec3Parameters(nsec3s);
        if (params == null) {
            return false;
        }

        return !this.validIterations(params, dnskeyRrset);
    }

    /**
     * Determine if the set of NSEC3 records provided with a response prove NAME
     * ERROR. This means that the NSEC3s prove a) the closest encloser exists,
     * b) the direct child of the closest encloser towards qname doesn't exist,
     * and c) *.closest encloser does not exist.
     * 
     * @param nsec3s The list of NSEC3s.
     * @param qname The query name to check against.
     * @param zonename This is the name of the zone that the NSEC3s belong to.
     *            This may be discovered in any number of ways. A good one is to
     *            use the signerName from the NSEC3 record's RRSIG.
     * @return {@link SecurityStatus#SECURE} of the Name Error is proven by the
     *         NSEC3 RRs, {@link SecurityStatus#BOGUS} if not,
     *         {@link SecurityStatus#INSECURE} if all of the NSEC3s could be
     *         validly ignored.
     */
    public SecurityStatus proveNameError(List<NSEC3Record> nsec3s, Name qname, Name zonename) {
        if (nsec3s == null || nsec3s.size() == 0) {
            return SecurityStatus.BOGUS;
        }

        NSEC3Parameters nsec3params = this.nsec3Parameters(nsec3s);
        if (nsec3params == null) {
            logger.debug("Could not find a single set of NSEC3 parameters (multiple parameters present).");
            return SecurityStatus.INSECURE;
        }

        // First locate and prove the closest encloser to qname. We will use the
        // variant that fails if the closest encloser turns out to be qname.
        CEResponse ce = this.proveClosestEncloser(qname, zonename, nsec3s, nsec3params);

        if (ce == null || ce.status != SecurityStatus.SECURE) {
            logger.debug("proveNameError: failed to prove a closest encloser.");
            return ce == null ? SecurityStatus.INSECURE : ce.status;
        }

        // At this point, we know that qname does not exist. Now we need to
        // prove
        // that the wildcard does not exist.
        Name wc = this.ceWildcard(ce.closestEncloser);
        byte[] wcHash = this.hash(wc, nsec3params);
        NSEC3Record nsec3 = this.findCoveringNSEC3(wcHash, zonename, nsec3s, nsec3params);
        if (nsec3 == null) {
            logger.debug("proveNameError: could not prove that the applicable wildcard did not exist.");
            return SecurityStatus.BOGUS;
        }

        if ((ce.ncNsec3.getFlags() & Flags.OPT_OUT) == Flags.OPT_OUT) {
            logger.debug("nsec3 nameerror proof: nc has optout");
            return SecurityStatus.INSECURE;
        }

        return SecurityStatus.SECURE;
    }

    /**
     * Determine if the NSEC3s provided in a response prove the NOERROR/NODATA
     * status. There are a number of different variants to this:
     * 
     * 1) Normal NODATA -- qname is matched to an NSEC3 record, type is not
     * present.
     * 
     * 2) ENT NODATA -- because there must be NSEC3 record for
     * empty-non-terminals, this is the same as #1.
     * 
     * 3) NSEC3 ownername NODATA -- qname matched an existing, lone NSEC3
     * ownername, but qtype was not NSEC3. NOTE: as of nsec-05, this case no
     * longer exists.
     * 
     * 4) Wildcard NODATA -- A wildcard matched the name, but not the type.
     * 
     * 5) Opt-In DS NODATA -- the qname is covered by an opt-in span and qtype
     * == DS. (or maybe some future record with the same parent-side-only
     * property)
     * 
     * @param nsec3s The NSEC3Records to consider.
     * @param qname The qname in question.
     * @param qtype The qtype in question.
     * @param zonename The name of the zone that the NSEC3s came from.
     * @return {@link SecurityStatus#SECURE} if the NSEC3s prove the
     *         proposition, {@link SecurityStatus#INSECURE} if qname is under
     *         opt-out, {@link SecurityStatus#BOGUS} otherwise.
     */
    public SecurityStatus proveNodata(List<NSEC3Record> nsec3s, Name qname, int qtype, Name zonename) {
        if (nsec3s == null || nsec3s.size() == 0) {
            return SecurityStatus.BOGUS;
        }

        NSEC3Parameters nsec3params = this.nsec3Parameters(nsec3s);
        if (nsec3params == null) {
            logger.debug("could not find a single set of NSEC3 parameters (multiple parameters present)");
            return SecurityStatus.BOGUS;
        }

        NSEC3Record nsec3 = this.findMatchingNSEC3(this.hash(qname, nsec3params), zonename, nsec3s, nsec3params);
        // Cases 1 & 2.
        if (nsec3 != null) {
            if (nsec3.hasType(qtype)) {
                logger.debug("proveNodata: Matching NSEC3 proved that type existed!");
                return SecurityStatus.BOGUS;
            }

            if (nsec3.hasType(Type.CNAME)) {
                logger.debug("proveNodata: Matching NSEC3 proved that a CNAME existed!");
                return SecurityStatus.BOGUS;
            }

            if (qtype == Type.DS && qname.labels() != 1 && nsec3.hasType(Type.SOA) && !Name.root.equals(qname)) {
                logger.debug("proveNodata: apex NSEC3 abused for no DS proof, bogus");
                return SecurityStatus.BOGUS;
            }
            else if (qtype != Type.DS && nsec3.hasType(Type.NS) && !nsec3.hasType(Type.SOA)) {
                if (!nsec3.hasType(Type.DS)) {
                    logger.debug("proveNodata: matching NSEC3 is insecure delegation");
                }
                else {
                    logger.debug("proveNodata: matching NSEC3 is a delegation, bogus");
                }

                return SecurityStatus.BOGUS;
            }

            return SecurityStatus.SECURE;
        }

        // For cases 3 - 5, we need the proven closest encloser, and it can't
        // match qname. Although, at this point, we know that it won't since we
        // just checked that.
        CEResponse ce = this.proveClosestEncloser(qname, zonename, nsec3s, nsec3params);

        // At this point, not finding a match or a proven closest encloser is a
        // problem.
        if (ce == null || ce.status == SecurityStatus.BOGUS) {
            logger.debug("proveNodata: did not match qname, nor found a proven closest encloser.");
            return SecurityStatus.BOGUS;
        }
        else if (ce.status == SecurityStatus.INSECURE && qtype != Type.DS) {
            logger.debug("proveNodata: closest nsec3 is insecure delegation.");
            return SecurityStatus.INSECURE;
        }

        // Case 3: REMOVED

        // Case 4:
        Name wc = this.ceWildcard(ce.closestEncloser);
        nsec3 = this.findMatchingNSEC3(this.hash(wc, nsec3params), zonename, nsec3s, nsec3params);
        if (nsec3 != null) {
            if (nsec3.hasType(qtype)) {
                logger.debug("proveNodata: matching wildcard had qtype!");
                return SecurityStatus.BOGUS;
            }
            else if (nsec3.hasType(Type.CNAME)) {
                logger.debug("nsec3 nodata proof: matching wildcard had a CNAME, bogus");
                return SecurityStatus.BOGUS;
            }

            if (qtype == Type.DS && qname.labels() != 1 && nsec3.hasType(Type.SOA)) {
                logger.debug("nsec3 nodata proof: matching wildcard for no DS proof has a SOA, bogus");
                return SecurityStatus.BOGUS;
            }
            else if (qtype != Type.DS && nsec3.hasType(Type.NS) && !nsec3.hasType(Type.SOA)) {
                logger.debug("nsec3 nodata proof: matching wilcard is a delegation, bogus");
                return SecurityStatus.BOGUS;
            }

            if (ce.ncNsec3 != null && (ce.ncNsec3.getFlags() & Flags.OPT_OUT) == Flags.OPT_OUT) {
                logger.debug("nsec3 nodata proof: matching wildcard is in optout range, insecure");
                return SecurityStatus.INSECURE;
            }

            return SecurityStatus.SECURE;
        }

        // Case 5.
        // Due to forwarders, cnames, and other collating effects, we
        // can see the ordinary unsigned data from a zone beneath an
        // insecure delegation under an optout here */
        if (ce.ncNsec3 == null) {
            logger.debug("nsec3 nodata proof: no next closer nsec3");
            return SecurityStatus.BOGUS;
        }

        // We need to make sure that the covering NSEC3 is opt-out.
        if ((ce.ncNsec3.getFlags() & Flags.OPT_OUT) == 0) {
            if (qtype != Type.DS) {
                logger.debug("proveNodata: covering NSEC3 was not opt-out in an opt-out DS NOERROR/NODATA case.");
            }
            else {
                logger.debug("proveNodata: could not find matching NSEC3, nor matching wildcard, and qtype is not DS -- no more options.");
            }

            return SecurityStatus.BOGUS;
        }

        // RFC5155 section 9.2: if nc has optout then no AD flag set
        return SecurityStatus.INSECURE;
    }

    /**
     * Prove that a positive wildcard match was appropriate (no direct match
     * RRset).
     * 
     * @param nsec3s The NSEC3 records to work with.
     * @param qname The qname that was matched to the wildard
     * @param zonename The name of the zone that the NSEC3s come from.
     * @param wildcard The purported wildcard that matched.
     * @return true if the NSEC3 records prove this case.
     */
    public boolean proveWildcard(List<NSEC3Record> nsec3s, Name qname, Name zonename, Name wildcard) {
        if (nsec3s == null || nsec3s.size() == 0 || qname == null || wildcard == null) {
            return false;
        }

        NSEC3Parameters nsec3params = this.nsec3Parameters(nsec3s);
        if (nsec3params == null) {
            logger.debug("couldn't find a single set of NSEC3 parameters (multiple parameters present).");
            return false;
        }

        // We know what the (purported) closest encloser is by just looking at
        // the
        // supposed generating wildcard.
        CEResponse candidate = new CEResponse(new Name(wildcard, 1), null);

        // Now we still need to prove that the original data did not exist.
        // Otherwise, we need to show that the next closer name is covered.
        Name nextClosest = nextClosest(qname, candidate.closestEncloser);
        candidate.ncNsec3 = this.findCoveringNSEC3(this.hash(nextClosest, nsec3params), zonename, nsec3s, nsec3params);

        if (candidate.ncNsec3 == null) {
            logger.debug("proveWildcard: did not find a covering NSEC3 that covered the next closer name to " + qname + " from " + candidate.closestEncloser
                    + " (derived from wildcard " + wildcard + ")");
            return false;
        }

        return true;
    }

    /**
     * Prove that a DS response either had no DS, or wasn't a delegation point.
     * 
     * Fundamentally there are two cases here: normal NODATA and Opt-In NODATA.
     * 
     * @param nsec3s The NSEC3 RRs to examine.
     * @param qname The name of the DS in question.
     * @param zonename The name of the zone that the NSEC3 RRs come from.
     * 
     * @return SecurityStatus.SECURE if it was proven that there is no DS in a
     *         secure (i.e., not opt-in) way, SecurityStatus.INSECURE if there
     *         was no DS in an insecure (i.e., opt-in) way,
     *         SecurityStatus.INDETERMINATE if it was clear that this wasn't a
     *         delegation point, and SecurityStatus.BOGUS if the proofs don't
     *         work out.
     */
    public SecurityStatus proveNoDS(List<NSEC3Record> nsec3s, Name qname, Name zonename) {
        if (nsec3s == null || nsec3s.size() == 0) {
            return SecurityStatus.BOGUS;
        }

        NSEC3Parameters nsec3params = this.nsec3Parameters(nsec3s);
        if (nsec3params == null) {
            logger.debug("couldn't find a single set of NSEC3 parameters (multiple parameters present).");
            return SecurityStatus.BOGUS;
        }

        // Look for a matching NSEC3 to qname -- this is the normal NODATA case.
        NSEC3Record nsec3 = this.findMatchingNSEC3(this.hash(qname, nsec3params), zonename, nsec3s, nsec3params);

        if (nsec3 != null) {
            // If the matching NSEC3 has the SOA bit set, it is from the wrong
            // zone (the child instead of the parent). If it has the DS bit set,
            // then we were lied to.
            if (nsec3.hasType(Type.SOA) || nsec3.hasType(Type.DS)) {
                return SecurityStatus.BOGUS;
            }

            // If the NSEC3 RR doesn't have the NS bit set, then this wasn't a
            // delegation point.
            if (!nsec3.hasType(Type.NS)) {
                return SecurityStatus.INDETERMINATE;
            }

            // Otherwise, this proves no DS.
            return SecurityStatus.SECURE;
        }

        // Otherwise, we are probably in the opt-in case.
        CEResponse ce = this.proveClosestEncloser(qname, zonename, nsec3s, nsec3params);
        if (ce == null || ce.status != SecurityStatus.SECURE) {
            return SecurityStatus.BOGUS;
        }

        // If we had the closest encloser proof, then we need to check that the
        // covering NSEC3 was opt-in -- the proveClosestEncloser step already
        // checked to see if the closest encloser was a delegation or DNAME.
        if (ce.ncNsec3.getFlags() == 1) {
            return SecurityStatus.SECURE;
        }

        return SecurityStatus.BOGUS;
    }

}
