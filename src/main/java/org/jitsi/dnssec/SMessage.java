/*
request.getHeader().setFlag(Flags.CD); * $Id: SMessage.java 321 2006-05-17 22:50:03Z davidb $
 * 
 * Copyright (c) 2005 VeriSign. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer. 2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution. 3. The name of the author may not
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 */

package org.jitsi.dnssec;

import java.util.*;

import org.xbill.DNS.*;

/**
 * This class represents a DNS message with resolver/validator state.
 * 
 * @author davidb
 * @version $Revision: 321 $
 */
public class SMessage {
    private Header header;
    private Record question;
    private OPTRecord oPTRecord;
    private List<SRRset>[] sections;
    private SecurityStatus securityStatus;

    private static SRRset[] empty_srrset_array = new SRRset[0];

    @SuppressWarnings("unchecked")
    public SMessage(Header h) {
        sections = new List[3];
        header = h;
        securityStatus = SecurityStatus.UNCHECKED;
    }

    public SMessage(int id) {
        this(new Header(id));
    }

    public SMessage() {
        this(new Header(0));
    }

    public SMessage(Message m) {
        this(m.getHeader());
        question = m.getQuestion();
        oPTRecord = m.getOPT();

        for (int i = Section.ANSWER; i <= Section.ADDITIONAL; i++) {
            RRset[] rrsets = m.getSectionRRsets(i);

            for (int j = 0; j < rrsets.length; j++) {
                addRRset(rrsets[j], i);
            }
        }
    }

    public Header getHeader() {
        return header;
    }

    public void setQuestion(Record r) {
        question = r;
    }

    public Record getQuestion() {
        return question;
    }

    public void setOPT(OPTRecord r) {
        oPTRecord = r;
    }

    public OPTRecord getOPT() {
        return oPTRecord;
    }

    public List<SRRset> getSectionList(int section) {
        if (section <= Section.QUESTION || section > Section.ADDITIONAL)
            throw new IllegalArgumentException("Invalid section.");

        if (sections[section - 1] == null) {
            sections[section - 1] = new LinkedList<SRRset>();
        }

        return sections[section - 1];
    }

    public void addRRset(SRRset srrset, int section) {
        if (section <= Section.QUESTION || section > Section.ADDITIONAL)
            throw new IllegalArgumentException("Invalid section");

        if (srrset.getType() == Type.OPT) {
            oPTRecord = (OPTRecord) srrset.first();
            return;
        }

        List<SRRset> sectionList = getSectionList(section);
        sectionList.add(srrset);
    }

    public void addRRset(RRset rrset, int section) {
        if (rrset instanceof SRRset) {
            addRRset((SRRset) rrset, section);
            return;
        }

        SRRset srrset = new SRRset(rrset);
        addRRset(srrset, section);
    }

    public SRRset[] getSectionRRsets(int section) {
        List<SRRset> slist = getSectionList(section);

        return slist.toArray(empty_srrset_array);
    }

    public SRRset[] getSectionRRsets(int section, int qtype) {
        List<SRRset> slist = getSectionList(section);

        if (slist.size() == 0)
            return new SRRset[0];

        ArrayList<SRRset> result = new ArrayList<SRRset>(slist.size());
        for (SRRset rrset : slist) {
            if (rrset.getType() == qtype)
                result.add(rrset);
        }

        return result.toArray(empty_srrset_array);
    }

    public int getRcode() {
        // FIXME: might want to do what Message does and handle extended rcodes.
        return header.getRcode();
    }

    public SecurityStatus getStatus() {
        return securityStatus;
    }

    public void setStatus(SecurityStatus status) {
        securityStatus = status;
    }

    public Message getMessage() {
        // Generate our new message.
        Message m = new Message(header.getID());

        // Convert the header
        // We do this for two reasons:
        // 1) setCount() is package scope, so we can't do that, and
        // 2) setting the header on a message after creating the
        // message frequently gets stuff out of sync, leading to malformed wire
        // format messages.
        Header h = m.getHeader();
        h.setOpcode(header.getOpcode());
        h.setRcode(header.getRcode());
        for (int i = 0; i < 16; i++) {
            if (Flags.isFlag(i) && header.getFlag(i))
                h.setFlag(i);
        }

        // Add all the records. -- this will set the counts correctly in the
        // message header.

        if (question != null) {
            m.addRecord(question, Section.QUESTION);
        }

        for (int sec = Section.ANSWER; sec <= Section.ADDITIONAL; sec++) {
            List<SRRset> slist = getSectionList(sec);
            for (SRRset rrset : slist) {
                for (Iterator<?> j = rrset.rrs(); j.hasNext();) {
                    m.addRecord((Record) j.next(), sec);
                }
                for (Iterator<?> j = rrset.sigs(); j.hasNext();) {
                    m.addRecord((Record) j.next(), sec);
                }
            }
        }

        if (oPTRecord != null) {
            m.addRecord(oPTRecord, Section.ADDITIONAL);
        }

        return m;
    }

    public int getCount(int section) {
        if (section == Section.QUESTION) {
            return question == null ? 0 : 1;
        }
        List<SRRset> sectionList = getSectionList(section);
        if (sectionList == null)
            return 0;
        if (sectionList.size() == 0)
            return 0;

        int count = 0;
        for (SRRset sr : sectionList) {
            count += sr.size();
        }
        return count;
    }

    public String toString() {
        return getMessage().toString();
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
        if (section <= Section.QUESTION || section > Section.ADDITIONAL)
            throw new IllegalArgumentException("Invalid section.");

        SRRset[] rrsets = getSectionRRsets(section);

        for (int i = 0; i < rrsets.length; i++) {
            if (rrsets[i].getName().equals(name) && rrsets[i].getType() == type && rrsets[i].getDClass() == dclass) {
                return rrsets[i];
            }
        }

        return null;
    }

    /**
     * Find an "answer" RRset. This will look for RRsets in the ANSWER section
     * that match the <qname,qtype,qclass>, taking into consideration CNAMEs.
     * 
     * @param qname The starting search name.
     * @param qtype The search type.
     * @param qclass The search class.
     * 
     * @return a SRRset matching the query. This SRRset may have a different
     *         name from qname, due to following a CNAME chain.
     */
    public SRRset findAnswerRRset(Name qname, int qtype, int qclass) {
        SRRset[] srrsets = getSectionRRsets(Section.ANSWER);

        for (int i = 0; i < srrsets.length; i++) {
            if (srrsets[i].getName().equals(qname) && srrsets[i].getType() == Type.CNAME) {
                CNAMERecord cname = (CNAMERecord) srrsets[i].first();
                qname = cname.getTarget();
                continue;
            }

            if (srrsets[i].getName().equals(qname) && srrsets[i].getType() == qtype && srrsets[i].getDClass() == qclass) {
                return srrsets[i];
            }
        }

        return null;
    }
}