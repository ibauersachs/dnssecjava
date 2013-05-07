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

import org.jitsi.dnssec.SRRset;
import org.xbill.DNS.Name;


/**
 * This is the per-event state object for the ValidatingResolver module.
 * 
 * @author davidb
 * @version $Revision: 286 $
 */
public class ValEventState {
    public static final int INIT_STATE = 0;
    public static final int PRIME_RESP_STATE = 1;
    public static final int FINDKEY_STATE = 2;
    public static final int FINDKEY_DS_RESP_STATE = 3;
    public static final int FINDKEY_DNSKEY_RESP_STATE = 4;
    public static final int VALIDATE_STATE = 5;
    public static final int CNAME_STATE = 6;
    public static final int CNAME_RESP_STATE = 7;
    public static final int CNAME_ANS_RESP_STATE = 8;
    public static final int FINISHED_STATE = 9;

    /** This is the next (or current) state for the attached event. */
    protected int state;
    /** This is the "final" state for the event. */
    protected int finalState;
    protected SRRset trustAnchorRRset;
    protected SRRset dsRRset;
    protected Name emptyDSName;
    protected KeyEntry keyEntry;
    protected int subtype;
    protected Name signerName;
    protected int cnameIndex;
    protected Name cnameSname;

    public ValEventState() {
        // defaults.
        state = INIT_STATE;
        finalState = FINISHED_STATE;
    }
}
