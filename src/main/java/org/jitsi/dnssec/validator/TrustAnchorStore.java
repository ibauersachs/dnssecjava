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

import java.util.HashMap;
import java.util.Map;

import org.jitsi.dnssec.SRRset;
import org.jitsi.dnssec.SecurityStatus;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;

/**
 * Storage for DS or DNSKEY records that are known to be trusted.
 * 
 * @author davidb
 * @version $Revision: 286 $
 */
public class TrustAnchorStore {
    private Map<String, SRRset> map;

    /**
     * Creates a new instance of this class.
     */
    public TrustAnchorStore() {
        this.map = new HashMap<String, SRRset>();
    }

    /**
     * Stores the given RRset as known trusted keys. Existing keys for the same
     * name and class are overwritten.
     * 
     * @param rrset The key set to store as trusted.
     */
    public void store(SRRset rrset) {
        if (rrset.getType() != Type.DS && rrset.getType() != Type.DNSKEY) {
            throw new IllegalArgumentException("Trust anchors can only be DS or DNSKEY records");
        }

        String k = this.key(rrset.getName(), rrset.getDClass());
        rrset.setSecurityStatus(SecurityStatus.SECURE);
        this.map.put(k, rrset);
    }

    /**
     * Gets the closest trusted key for the given name or <code>null</code> if
     * no match is found.
     * 
     * @param name The name to search for.
     * @param dclass The class of the keys.
     * @return The closest found key for <code>name</code> or <code>null</code>.
     */
    public SRRset find(Name name, int dclass) {
        while (name.labels() > 0) {
            String k = this.key(name, dclass);
            SRRset r = this.lookup(k);
            if (r != null) {
                return r;
            }

            name = new Name(name, 1);
        }

        return null;
    }

    private SRRset lookup(String key) {
        return this.map.get(key);
    }

    private String key(Name n, int dclass) {
        return "T" + dclass + "/" + n;
    }
}
