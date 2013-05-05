package org.jitsi;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DSRecord;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSEC3Record;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;
import org.xbill.DNS.DNSSEC.DNSSECException;

public class DnssecResolver extends SimpleResolver {
    private Set<DSRecord> anchors = new HashSet<DSRecord>();

    public DnssecResolver(String hostname) throws UnknownHostException {
        super(hostname);
        super.setEDNS(0, 0, ExtendedFlags.DO, null);
        super.setIgnoreTruncation(false);
    }

    public DnssecResolver() throws UnknownHostException {
        super.setEDNS(0, 0, ExtendedFlags.DO, null);
        super.setIgnoreTruncation(false);
    }

    @Override
    public Message send(Message query) throws IOException {
        return send(query, true);
    }

    protected Message send(Message query, boolean validate) throws IOException {
        Set<DNSKEYRecord> trustedKeys = new HashSet<DNSKEYRecord>();
        return send(query, true, trustedKeys);
    }

    protected Message send(Message query, boolean validate, Set<DNSKEYRecord> trustedKeys) throws IOException {
        query.getHeader().setFlag(Flags.CD);
        Message result = super.send(query);
        if (validate) {
            try {
                validateDnssec(query, result, trustedKeys);
            }
            catch (DNSSECException e) {
                throw new RuntimeException(e);
//                result.getHeader().setRcode(Rcode.SERVFAIL);
            }
        }

        return result;
    }

    @SuppressWarnings("unchecked")
    protected void validateDnssec(Message query, Message result, Set<DNSKEYRecord> trustedKeys) throws DNSSECException, IOException {
//        // do not recursively validate DNSSEC queries
//        switch (query.getQuestion().getType()) {
//            case Type.RRSIG:
//            case Type.DNSKEY:
//            case Type.DS:
//            case Type.NSEC:
//            case Type.NSEC3:
//            case Type.NSEC3PARAM:
//                return;
//        }

        if (anchors.size() == 0) {
            throw new GenericDNSSECException("Not trust anchors defined, cannot validate.");
        }

        if (result.getRcode() == Rcode.NXDOMAIN) {
            // proof non-existence
            // get DS for zone, the authority section refers us to the zone-cut (unvalidated)
            proofNonExistence(query.getQuestion(), result.getSectionRRsets(Section.AUTHORITY), trustedKeys);
            result.getHeader().setFlag(Flags.AD);
        }
        else if (result.getRcode() == Rcode.NOERROR) {
            RRset[] answerSets = result.getSectionRRsets(Section.ANSWER);
            if (answerSets.length == 0) {
                // proof non-existence
                // authority contains:
                // - SOA (possibly signed)
                // - NSEC(3) with signatures, if the zone is signed
                proofNonExistence(query.getQuestion(), result.getSectionRRsets(Section.AUTHORITY), trustedKeys);
            }

            int secureCount = 0;
            for(RRset set : answerSets) {
                Iterator<RRSIGRecord> sigs = set.sigs();
                int sigCount = 0;
                while (sigs.hasNext()) {
                    sigs.next();
                    sigCount++;
                }
    
                System.out.println("Found " + sigCount + " RRSIGs over " + Type.string(query.getQuestion().getType()) + " RRset");
                if (sigCount == 0) {
                    // proof non-existence
                    // the authority section refers us to the zone apex (not validated)
                    proofNonExistence(query.getQuestion(), result.getSectionRRsets(Section.AUTHORITY), trustedKeys);
                }
                else {
                    validateSignature(set, result.getSectionRRsets(Section.AUTHORITY), trustedKeys);
                    secureCount++;
                }
            }

            if (secureCount == answerSets.length) {
                result.getHeader().setFlag(Flags.AD);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void proofNonExistence(Record query, RRset[] sets, Set<DNSKEYRecord> trustedKeys) throws IOException {
        // no authority information was passed from the original query -> obtain from SOA query
        final Record soaQuestion = Record.newRecord(query.getName(), Type.SOA, DClass.IN);
        if (sets.length == 0 && !query.equals(soaQuestion)) {
            // TODO: use a cache for this query
            final Message soaQuery = Message.newQuery(soaQuestion);
            final Message response = send(soaQuery, true, trustedKeys);
            sets = response.getSectionRRsets(Section.AUTHORITY);
        }

        int count = 0;
        for (RRset authSet : sets) {
            Iterator<RRSIGRecord> sigs = authSet.sigs();
            int sigCount = 0;
            while (sigs.hasNext()) {
                sigs.next();
                sigCount++;
            }

            System.out.println("Found " + sigCount + " RRSIGs over " + Type.string(query.getType()) + " RRset for " + query.getName());
            if (sigCount == 0) {
                Iterator<Record> auth = authSet.rrs();
                while (auth.hasNext()) {
                    Record authRecord = auth.next();
                    if (authRecord instanceof SOARecord
                            || authRecord instanceof NSRecord) {
                        if (getRecords(authRecord.getName(), Type.DS, trustedKeys).size() == 0) {
                            return;
                        }
                    }
                    else if (authRecord instanceof NSECRecord
                            || authRecord instanceof NSEC3Record) {
                        throw new GenericDNSSECException("NSEC record without signature found.");
                    }
                }
            }
            else {
                // if there's something signed, we assume there is NSEC(3) data to proof the non-existence
                // first validate the data we got:
                validateSignature(authSet, null, trustedKeys);
                count++;
            }
        }

        if (count == sets.length) {
            System.out.println("All signatures validated or recursively proofed to be non-existent");
            List<NSECRecord> nsecs = new ArrayList<NSECRecord>(2);
            List<NSEC3Record> nsec3s = new ArrayList<NSEC3Record>(2);
            for (RRset set : sets) {
                Iterator<Record> it = set.rrs();
                while (it.hasNext()) {
                    Record r = it.next();
                    if (r instanceof NSECRecord) {
                        NSECRecord ns = (NSECRecord)r;
                        nsecs.add(ns);
                    }
                    else if (r instanceof NSEC3Record) {
                        NSEC3Record ns = (NSEC3Record)r;
                        // rfc5155#section-8.2
                        if (ns.getFlags() == 0 || ns.getFlags() == 1) {
                            nsec3s.add(ns);
                        }
                    }
                }
            }

            System.out.println("Found " + nsecs.size() + " NSEC and " + nsec3s.size() + " NSEC3 records:");
            Name question = query.getName();
            if (nsecs.size() > 0) {
                for (NSECRecord n : nsecs) {
                    System.out.println("    " + n);
                }

                for (NSECRecord ns : nsecs) {
                    if (    //rfc4035#section-5.4, bullet 1, part 1 (part 2 is checked in validateSignature)
                            (ns.getName().equals(question) && !ns.hasType(query.getType()))
                            //rfc4035#section-5.4, bullet 2
                            || (ns.getName().compareTo(question) < 0 && question.compareTo(ns.getNext()) < 0)) {
                        System.out.println("NSEC validated that " + question + "/" + Type.string(query.getType()) + " does not exist");
                        return;
                    }
                }
            }

            if (nsec3s.size() > 0) {
                for (NSEC3Record n : nsec3s) {
                    System.out.println("    " + n);
                }

                throw new GenericDNSSECException("Not implemented: NSEC3 non-existence validation");
            }

            throw new GenericDNSSECException("NSEC(3) could not validate non-existence of " + question + "/" + Type.string(query.getType()));
        }

        throw new GenericDNSSECException("No authority section for " + query);
    }

    @SuppressWarnings("unchecked")
    private void validateSignature(RRset set, RRset[] authorityData, Set<DNSKEYRecord> trustedKeys) throws IOException {
        boolean atLeastOneSignatureValid = false;
        Iterator<RRSIGRecord> sigs = set.sigs();
        while (sigs.hasNext()) {
            RRSIGRecord sig = sigs.next();
            DNSKEYRecord key = null;

            // check if this is a self-signed key
            Iterator<Record> rrit = set.rrs();
            while (rrit.hasNext()) {
                Record record = rrit.next();
                if (record instanceof DNSKEYRecord) {
                    DNSKEYRecord setKey = (DNSKEYRecord)record;
                    if ((setKey.getFlags() & DNSKEYRecord.Flags.ZONE_KEY) == DNSKEYRecord.Flags.ZONE_KEY
                            && (setKey.getFlags() & DNSKEYRecord.Flags.REVOKE) == 0
                            && setKey.getName().equals(sig.getSigner())
                            && setKey.getFootprint() == sig.getFootprint()) {
                        System.out.println("Key " + setKey.getName() + "/" + setKey.getFootprint() + "/" + setKey.getAlgorithm() + " found in result set (self-signed)");
                        key = setKey;
                        if (atLeastOneSignatureValid) {
                            trustedKeys.add(key);
                        }
                    }
                }
            }

            if (key == null) {
                key = getDnskey(sig.getSigner(), sig.getFootprint(), trustedKeys);
                trustedKeys.add(key); // keys we get from DNS are safe due to recursive validation
            }

            System.out.println("Validating sig for " + sig.getName() + "/" + Type.string(sig.getTypeCovered()));
            try {
                DNSSEC.verify(set, sig, key, getCurrentDate());
                if (!trustedKeys.contains(key)) {
                    DSRecord ds = getDs(key, trustedKeys);
                    DSRecord keyDigest = new DSRecord(Name.root, DClass.IN, 0, ds.getDigestID(), key);
                    if (Arrays.equals(ds.getDigest(), keyDigest.getDigest())) {
                        System.out.println("--> DS " + key.getName().toString() + "/" + ds.getFootprint() + "/" + ds.getAlgorithm() + " verifies DNSKEY=" + key.getName() + "/" + key.getFootprint() + "/" + key.getAlgorithm());
                        trustedKeys.add(key);
                    }
                    else {
                        throw new GenericDNSSECException("Failed to validate DNSKEY " + key.getName() + "/" + key.getFootprint());
                    }
                }

                // When the result was expanded from a wildcard, check that no more precise match was available.
                // rfc4035#section-3.1.3.3 mandates that a wilcard answer has NSEC(3) data available in the authority section.
                // The label count of the signature defines the root-zone as 0,
                // while the root-zone counts in DNSJAVA as one label, hence the +1
                if (sig.getLabels() + 1 != sig.getName().labels()) {
                    /*boolean hasNsec = false;
                    for (RRset s : authorityData) {
                        Iterator<Record> rrs = s.rrs();
                        while (rrs.hasNext()) {
                            Record record = rrs.next();
                            if (record instanceof NSECRecord || record instanceof NSEC3Record) {
                                hasNsec = true;
                                break;
                            }
                        }

                        if (hasNsec) {
                            validateSignature(s, null, trustedKeys);
                            
                        }
                    }

                    if (!hasNsec) {
                        throw new GenericDNSSECException("Wildcard expansion without NSEC in the authority");
                    }*/
                    Iterator<Record> rrs = set.rrs();
                    while (rrs.hasNext()) {
                        Record record = rrs.next();
                        proofNonExistence(record, authorityData, trustedKeys);
                    }

                    throw new GenericDNSSECException("Not implemented: check NSEC(3) that there was no more precise match than the wildcard " + sig.getLabels() + "/" + sig.getName().labels());
                }

                atLeastOneSignatureValid = true;
            }
            catch (Exception ex) {
                System.out.println("! Key " + sig.getSigner() + "/" + key.getFootprint() + "/" + key.getAlgorithm() + " does not verify the RRset: " + ex.getMessage());
            }
        }

        if (!atLeastOneSignatureValid) {
            throw new GenericDNSSECException("None of the signatures for were valid.");
        }
    }

    private void proofNoExactMatchOnWildcard() {
        
    }

    private DSRecord getDs(DNSKEYRecord key, Set<DNSKEYRecord> trustedKeys) throws IOException {
        for (DSRecord ds : anchors) {
            if (ds.getName().equals(key.getName()) && ds.getFootprint() == key.getFootprint()) {
                System.out.println("DS for " + key.getName() + "/" + key.getFootprint() + "/" + key.getAlgorithm() + " found in trust-anchors.");
                return ds;
            }
        }

        List<DSRecord> l = getRecords(key.getName(), Type.DS, trustedKeys);
        for (DSRecord ds : l) {
            if (ds.getName().equals(key.getName())
                    && ds.getFootprint() == key.getFootprint()) {
                System.out.println("DS for " + key.getName() + "/" + key.getFootprint() + "/" + key.getAlgorithm() + " found in DNS.");
                return ds;
            }
        }

        throw new GenericDNSSECException("DS for " + key.getName() + "/" + key.getFootprint() + "/" + key.getAlgorithm() + " not found");
    }

    private DNSKEYRecord getDnskey(Name signer, int footprint, Set<DNSKEYRecord> trustedKeys) throws IOException {
        for (DNSKEYRecord key : trustedKeys) {
            if (key.getName().equals(signer) && key.getFootprint() == footprint) {
                System.out.println("Key " + signer + "/" + footprint + "/" + key.getAlgorithm() + " found in trusted keys");
                return key;
            }
        }

        List<DNSKEYRecord> l = getRecords(signer, Type.DNSKEY, trustedKeys);
        for (DNSKEYRecord key : l) {
            if ((key.getFlags() & DNSKEYRecord.Flags.ZONE_KEY) == DNSKEYRecord.Flags.ZONE_KEY
                    && (key.getFlags() & DNSKEYRecord.Flags.REVOKE) == 0
                    && key.getName().equals(signer)
                    && key.getFootprint() == footprint) {
                System.out.println("Key " + signer + "/" + footprint + "/" + key.getAlgorithm() + " found in DNS ");
                return key;
            }
        }

        throw new GenericDNSSECException("Key " + footprint + "/" + signer + " not found");
    }

    @SuppressWarnings("unchecked")
    private <T extends Record> List<T> getRecords(Name zone, int type, Set<DNSKEYRecord> trustedKeys) throws IOException {
        // TODO: use a cache for this query
        final Record question = Record.newRecord(zone, type, DClass.IN);
        final Message query = Message.newQuery(question);
        final Message response = send(query, true, trustedKeys);

        RRset[] rrsets = response.getSectionRRsets(Section.ANSWER);
        List<T> result = new LinkedList<T>();
        for (RRset set : rrsets) {
            Iterator<T> rrit = set.rrs();
            while (rrit.hasNext()) {
                result.add(rrit.next());
            }
        }

        return result;
    }

    public void addTrustAnchor(String anchor) throws NumberFormatException, IOException, DNSSECException {
        if (anchor == null) {
            throw new InvalidParameterException("anchor cannot be null");
        }

        String[] dsParts = anchor.split("\\s+");
        if (dsParts.length != 7 && dsParts.length != 8) {
            throw new InvalidParameterException("DS anchor must be in BIND format");
        }

        int ttlOffset = 0;
        int ttl = 0;
        try {
            ttl = Integer.parseInt(dsParts[1]);
            ttlOffset = 1;
        }
        catch (NumberFormatException nfe) {
        }

        String hexDigest = dsParts[6 + ttlOffset].trim();
        byte[] digest = new byte[hexDigest.length() / 2];
        for (int i = 0; i < hexDigest.length() / 2; i++) {
            digest[i] = (byte) Short.parseShort(hexDigest.substring(i * 2, i * 2 + 2), 16);
        }

        DSRecord ds = new DSRecord(Name.fromString(dsParts[0]), // .
                DClass.value(dsParts[1 + ttlOffset]), // IN
                ttlOffset == 0 ? 0 : ttl, // TTL
                Integer.parseInt(dsParts[3 + ttlOffset]), // digest id
                Integer.parseInt(dsParts[4 + ttlOffset]), // algId
                Integer.parseInt(dsParts[5 + ttlOffset]), // hash-type
                digest);

        this.anchors.add(ds);
    }

    protected Date getCurrentDate(){
        return new Date();
    }
}
