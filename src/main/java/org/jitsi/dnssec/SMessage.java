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

package org.jitsi.dnssec;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/**
 * This class represents a DNS message with validator state and some utility
 * methods.
 * 
 * @author davidb
 */
public class SMessage {
    private static final SRRset[] EMPTY_SRRSET_ARRAY = new SRRset[0];
    private static final int NUM_SECTIONS = 3;
    private static final int MAX_FLAGS = 16;
    private static final int EXTENDED_FLAGS_BIT_OFFSET = 4;

    private Header header;
    private Record question;
    private OPTRecord oPTRecord;
    private List<SRRset>[] sections;
    private SecurityStatus securityStatus;

    /**
     * Creates a instance of this class.
     * 
     * @param h The header of the original message.
     */
    @SuppressWarnings("unchecked")
    public SMessage(Header h) {
        this.sections = new List[NUM_SECTIONS];
        this.header = h;
        this.securityStatus = SecurityStatus.UNCHECKED;
    }

    /**
     * Creates a new instance of this class.
     * 
     * @param id The ID of the DNS query or response message.
     * @param question The question section of the query or response.
     */
    public SMessage(int id, Record question) {
        this(new Header(id));
        this.question = question;
    }

    /**
     * Creates a new instance of this class.
     * 
     * @param m The DNS message to wrap.
     */
    public SMessage(Message m) {
        this(m.getHeader());
        this.question = m.getQuestion();
        this.oPTRecord = m.getOPT();

        for (int i = Section.ANSWER; i <= Section.ADDITIONAL; i++) {
            RRset[] rrsets = m.getSectionRRsets(i);

            for (int j = 0; j < rrsets.length; j++) {
                addRRset(new SRRset(rrsets[j]), i);
            }
        }
    }

    /**
     * Gets the header of this message.
     * 
     * @return The header of this message.
     */
    public Header getHeader() {
        return this.header;
    }

    /**
     * Gets the question section of this message.
     * 
     * @return The question section of this message.
     */
    public Record getQuestion() {
        return this.question;
    }

    private List<SRRset> getSectionList(int section) {
        checkSectionValidity(section);

        if (this.sections[section - 1] == null) {
            this.sections[section - 1] = new LinkedList<SRRset>();
        }

        return this.sections[section - 1];
    }

    private void addRRset(SRRset srrset, int section) {
        checkSectionValidity(section);

        if (srrset.getType() == Type.OPT) {
            this.oPTRecord = (OPTRecord)srrset.first();
            return;
        }

        List<SRRset> sectionList = this.getSectionList(section);
        sectionList.add(srrset);
    }

    private void checkSectionValidity(int section) {
        if (section <= Section.QUESTION || section > Section.ADDITIONAL) {
            throw new IllegalArgumentException("Invalid section");
        }
    }

    /**
     * Gets signed RRsets for the queried section.
     * 
     * @param section The section whose RRsets are demanded.
     * @return Signed RRsets for the queried section.
     */
    public SRRset[] getSectionRRsets(int section) {
        List<SRRset> slist = this.getSectionList(section);
        return slist.toArray(EMPTY_SRRSET_ARRAY);
    }

    /**
     * Gets signed RRsets for the queried section.
     * 
     * @param section The section whose RRsets are demanded.
     * @param qtype Filter the results for these record types.
     * @return Signed RRsets for the queried section.
     */
    public SRRset[] getSectionRRsets(int section, int qtype) {
        List<SRRset> slist = this.getSectionList(section);

        if (slist.size() == 0) {
            return EMPTY_SRRSET_ARRAY;
        }

        List<SRRset> result = new ArrayList<SRRset>(slist.size());
        for (SRRset rrset : slist) {
            if (rrset.getType() == qtype) {
                result.add(rrset);
            }
        }

        return result.toArray(EMPTY_SRRSET_ARRAY);
    }

    /**
     * Gets the result code of the response message.
     * 
     * @return The result code of the response message.
     */
    public int getRcode() {
        int rcode = this.header.getRcode();
        if (this.oPTRecord != null) {
            rcode += this.oPTRecord.getExtendedRcode() << EXTENDED_FLAGS_BIT_OFFSET;
        }

        return rcode;
    }

    /**
     * Gets the security status of this message.
     * 
     * @return The security status of this message.
     */
    public SecurityStatus getStatus() {
        return this.securityStatus;
    }

    /**
     * Sets the security status for this message.
     * 
     * @param status the new security status for this message.
     */
    public void setStatus(SecurityStatus status) {
        this.securityStatus = status;
    }

    /**
     * Gets this message as a standard DNSJAVA message.
     * 
     * @return This message as a standard DNSJAVA message.
     */
    public Message getMessage() {
        // Generate our new message.
        Message m = new Message(this.header.getID());

        // Convert the header
        // We do this for two reasons:
        // 1) setCount() is package scope, so we can't do that, and
        // 2) setting the header on a message after creating the
        // message frequently gets stuff out of sync, leading to malformed wire
        // format messages.
        Header h = m.getHeader();
        h.setOpcode(this.header.getOpcode());
        h.setRcode(this.header.getRcode());
        for (int i = 0; i < MAX_FLAGS; i++) {
            if (Flags.isFlag(i) && this.header.getFlag(i)) {
                h.setFlag(i);
            }
        }

        // Add all the records. -- this will set the counts correctly in the
        // message header.
        if (this.question != null) {
            m.addRecord(this.question, Section.QUESTION);
        }

        for (int sec = Section.ANSWER; sec <= Section.ADDITIONAL; sec++) {
            List<SRRset> slist = this.getSectionList(sec);
            for (SRRset rrset : slist) {
                for (Iterator<?> j = rrset.rrs(); j.hasNext();) {
                    m.addRecord((Record)j.next(), sec);
                }

                for (Iterator<?> j = rrset.sigs(); j.hasNext();) {
                    m.addRecord((Record)j.next(), sec);
                }
            }
        }

        if (this.oPTRecord != null) {
            m.addRecord(this.oPTRecord, Section.ADDITIONAL);
        }

        return m;
    }

    /**
     * Gets the number of records.
     * 
     * @param section The section for which the records are counted.
     * @return The number of records for the queried section.
     */
    public int getCount(int section) {
        if (section == Section.QUESTION) {
            return 1;
        }

        List<SRRset> sectionList = this.getSectionList(section);
        if (sectionList.size() == 0) {
            return 0;
        }

        int count = 0;
        for (SRRset sr : sectionList) {
            count += sr.size();
        }

        return count;
    }

    /**
     * Find a specific (S)RRset in a given section.
     * 
     * @param name the name of the RRset.
     * @param type the type of the RRset.
     * @param dclass the class of the RRset.
     * @param section the section to look in (ANSWER -> ADDITIONAL)
     * 
     * @return The SRRset if found, null otherwise.
     */
    public SRRset findRRset(Name name, int type, int dclass, int section) {
        this.checkSectionValidity(section);

        SRRset[] rrsets = this.getSectionRRsets(section);

        for (int i = 0; i < rrsets.length; i++) {
            if (rrsets[i].getName().equals(name) && rrsets[i].getType() == type && rrsets[i].getDClass() == dclass) {
                return rrsets[i];
            }
        }

        return null;
    }

    /**
     * Find an "answer" RRset. This will look for RRsets in the ANSWER section
     * that match the <qname,qtype,qclass>, without considering CNAMEs.
     * 
     * @param qname The starting search name.
     * @param qtype The search type.
     * @param qclass The search class.
     * 
     * @return a SRRset matching the query. This SRRset may have a different
     *         name from qname, due to following a CNAME chain.
     */
    public SRRset findAnswerRRset(Name qname, int qtype, int qclass) {
        return this.findRRset(qname, qtype, qclass, Section.ANSWER);
    }
}
