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
 */

package org.jitsi.dnssec.unbound.rpl;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

import org.jitsi.dnssec.DateMock;
import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SystemMock;
import org.jitsi.dnssec.TestBase;
import org.junit.Test;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class UnboundTests extends TestBase {
    public void runUnboundTest() throws ParseException, IOException {
        InputStream data = getClass().getResourceAsStream("/unbound/" + testName + ".rpl");
        RplParser p = new RplParser(data);
        Rpl rpl = p.parse();
        if (rpl.nsec3iterations != null) {
            Properties config = new Properties();
            for (Entry<Integer, Integer> e : rpl.nsec3iterations.entrySet()) {
                config.put("org.jitsi.dnssec.nsec3.iterations." + e.getKey(), e.getValue());
            }

            resolver.init(config);
        }

        for (Message m : rpl.replays) {
            add(stripAdditional(m));
            for (RRset set : m.getSectionRRsets(Section.AUTHORITY)) {
                if (set.getType() == Type.DS && set.sigs().hasNext() && Name.fromString("sub.example.com.").equals(set.getName())) {
                    Message additional = new Message();
                    additional.addRecord(Record.newRecord(set.getName(), set.getType(), set.getDClass()), Section.QUESTION);
                    Iterator<?> it = set.rrs();
                    while (it.hasNext()) {
                        additional.addRecord((Record)it.next(), Section.ANSWER);
                    }

                    it = set.sigs();
                    while (it.hasNext()) {
                        additional.addRecord((Record)it.next(), Section.ANSWER);
                    }

                    add(stripAdditional(additional));
                    break;
                }
            }
        }

        // merge xNAME queries into one
        List<Message> copy = new ArrayList<Message>(rpl.replays.size());
        copy.addAll(rpl.replays);
        List<Name> copiedTargets = new ArrayList<Name>(5);
        for (Message m : copy) {
            Name target = null;
            for (RRset s : m.getSectionRRsets(Section.ANSWER)) {
                if (s.getType() == Type.CNAME) {
                    target = ((CNAMERecord)s.first()).getTarget();
                }
                else if (s.getType() == Type.DNAME) {
                    target = ((DNAMERecord)s.first()).getTarget();
                }

                while (target != null) {
                    Message a = get(target, m.getQuestion().getType());
                    if (a == null) {
                        a = get(target, Type.CNAME);
                    }

                    if (a == null) {
                        a = get(target, Type.DNAME);
                    }

                    if (a != null) {
                        target = add(m, a);
                        if (copiedTargets.contains(target)) {
                            break;
                        }

                        copiedTargets.add(target);
                        rpl.replays.remove(a);
                    }
                    else {
                        target = null;
                    }
                }
            }
        }

        // promote any DS records in auth. sections to real queries
        copy = new ArrayList<Message>(rpl.replays.size());
        copy.addAll(rpl.replays);
        for (Message m : copy) {
            for (RRset s : m.getSectionRRsets(Section.AUTHORITY)) {
                if (s.getType() == Type.DS) {
                    Message ds = new Message();
                    ds.addRecord(Record.newRecord(s.getName(), s.getType(), s.getDClass()), Section.QUESTION);
                    Iterator<?> rrs = s.rrs();
                    while (rrs.hasNext()) {
                        ds.addRecord((Record)rrs.next(), Section.ANSWER);
                    }

                    Iterator<?> sigs = s.sigs();
                    while (sigs.hasNext()) {
                        ds.addRecord((Record)sigs.next(), Section.ANSWER);
                    }

                    rpl.replays.add(ds);
                }
            }
        }

        clear();
        for (Message m : rpl.replays) {
            add(stripAdditional(m));
        }

        if (rpl.date != null) {
            SystemMock.overriddenMillis = rpl.date.getMillis();
            DateMock.overriddenMillis = rpl.date.getMillis();
        }

        if (rpl.trustAnchors != null) {
            resolver.getTrustAnchors().clear();
            for (SRRset rrset : rpl.trustAnchors) {
                resolver.getTrustAnchors().store(rrset);
            }
        }

        for (Check c : rpl.checks.values()) {
            Message s = resolver.send(c.query);
            assertEquals(c.response.getHeader().getFlag(Flags.AD), s.getHeader().getFlag(Flags.AD));
            assertEquals(Rcode.string(c.response.getRcode()), Rcode.string(s.getRcode()));
        }
    }

    private Message stripAdditional(Message m) {
        if (m.getQuestion().getType() == Type.RRSIG) {
            return m;
        }

        Message copy = new Message();
        copy.setHeader(m.getHeader());
        for (int i = 0; i < Section.ADDITIONAL; i++) {
            for (RRset set : m.getSectionRRsets(i)) {
                if (set.getType() == Type.NS && m.getQuestion().getType() != Type.NS) {
                    continue;
                }

                Iterator<?> rrs = set.rrs();
                while (rrs.hasNext()) {
                    copy.addRecord((Record)rrs.next(), i);
                }

                Iterator<?> sigs = set.sigs();
                while (sigs.hasNext()) {
                    copy.addRecord((Record)sigs.next(), i);
                }
            }
        }

        return copy;
    }

    private Name add(Message target, Message source) {
        Name next = null;
        target.getHeader().setRcode(source.getRcode());
        for (Record r : source.getSectionArray(Section.ANSWER)) {
            target.addRecord(r, Section.ANSWER);
            if (r.getType() == Type.CNAME) {
                next = ((CNAMERecord)r).getTarget();
            }
            else if (r.getType() == Type.DNAME) {
                next = ((DNAMERecord)r).getTarget();
            }
        }

        for (Record r : source.getSectionArray(Section.AUTHORITY)) {
            if (r.getType() != Type.NS) {
                target.addRecord(r, Section.AUTHORITY);
            }
        }

        return next;
    }

    public static void main(String[] srgs) throws ParseException, IOException {
        String[] ignored = new String[] { "val_faildnskey_ok.rpl", // tests an
                                                                   // unbound
                                                                   // specific
                                                                   // config
                                                                   // option
                "val_nsec3_nods_negcache.rpl", // we don't do negative caching
                "val_unsecds_negcache.rpl", // "
                "val_negcache_dssoa.rpl", // "
                "val_nsec3_b3_optout_negcache.rpl", // "
                "val_dsnsec.rpl", // "
                "val_refer_unsignadd.rpl", // more cache stuff
                "val_referglue.rpl", // "
                "val_noadwhennodo.rpl", // irrelevant - if we wouldn't want AD,
                                        // we wouldn't be using this stuff
                "val_fwdds.rpl", // irrelevant, we're not a recursive resolver
                "val_referd.rpl", // NSEC records missing for validation, tests
                                  // caching stuff
                "val_stubds.rpl", // tests unbound specific config (stub zones)
                "val_cnametonsec.rpl", // incomplete CNAME answer
                "val_cnametooptin.rpl", // incomplete CNAME answer
                "val_cnametoinsecure.rpl", // incomplete CNAME answer
                "val_nsec3_optout_cache.rpl", // more cache stuff
                "val_ds_gost.rpl", // we don't support GOST (RFC5933)
                "val_ds_gost_downgrade.rpl", // no GOST
                "val_unsecds_qtypeds.rpl", // tests the iterative resolver
                "val_anchor_nx.rpl", // tests caching of NX from a parent
                                     // resolver
                "val_anchor_nx_nosig.rpl", // "
        };
        List<String> ignoredList = Arrays.asList(ignored);

        for (String f : new File("./src/test/resources/unbound").list()) {
            if (ignoredList.contains(f)) {
                continue;
            }

            System.out.println("    @Test");
            System.out.println("    public void " + f.split("\\.")[0] + "() throws ParseException, IOException {");
            System.out.println("        runUnboundTest();");
            System.out.println("    }");
        }
    }

    @Test
    public void val_adbit() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_adcopy() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ans_dsent() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ans_nx() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_any() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_any_cname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_any_dname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnameinsectopos() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnamenx_dblnsec() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnamenx_rcodenx() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnameqtype() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametocloser() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametocloser_nosig() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametocnamewctoposwc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametodname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametodnametocnametopos() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametonodata() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametonodata_nonsec() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametonx() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametooptout() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametopos() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametoposnowc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnametoposwc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnamewctonodata() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnamewctonx() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cnamewctoposwc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cname_loop1() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cname_loop2() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_cname_loop3() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_dnametoolong() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_dnametopos() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_dnametoposwc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_dnamewc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ds_afterprime() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ds_cname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ds_cnamesub() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ds_sha2() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ds_sha2_downgrade() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_entds() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_faildnskey() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_keyprefetch() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_keyprefetch_verify() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_mal_wc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_negcache_ds() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodata() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodatawc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodatawc_badce() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodatawc_nodeny() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodatawc_one() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodata_ent() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodata_entwc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodata_failsig() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodata_hasdata() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nodata_zonecut() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nokeyprime() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b1_nameerror() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b1_nameerror_noce() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b1_nameerror_nonc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b1_nameerror_nowc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b21_nodataent() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b21_nodataent_wr() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b2_nodata() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b2_nodata_nons() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b3_optout() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b3_optout_noce() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b3_optout_nonc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b4_wild() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b4_wild_wr() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b5_wcnodata() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b5_wcnodata_noce() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b5_wcnodata_nonc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_b5_wcnodata_nowc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_cnametocnamewctoposwc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_cname_ds() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_cname_par() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_cname_sub() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_entnodata_optout() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_entnodata_optout_badopt() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_entnodata_optout_match() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_iter_high() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_nodatawccname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_nods() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_nods_badopt() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_nods_badsig() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_nods_soa() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_optout_ad() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_wcany() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nsec3_wcany_nodeny() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nodeny() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nowc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_collision() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_collision2() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_collision3() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_collision4() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_hashalg() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_nsecmix() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_nsec3_params() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_nx_overreach() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_positive() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_positive_nosigs() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_positive_wc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_positive_wc_nodeny() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_pos_truncns() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_qds_badanc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_qds_oneanc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_qds_twoanc() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_rrsig() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_secds() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_secds_nosig() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_stub_noroot() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ta_algo_dnskey() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_ta_algo_missing() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_twocname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_unalgo_anchor() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_unalgo_dlv() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_unalgo_ds() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_unsecds() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_unsec_cname() throws ParseException, IOException {
        runUnboundTest();
    }

    @Test
    public void val_wild_pos() throws ParseException, IOException {
        runUnboundTest();
    }
}
