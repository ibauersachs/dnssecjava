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

import org.jitsi.dnssec.validator.ValEventState;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

/**
 * This is the core event class. A DNSEvent represents either a request or a
 * request, response pair. Note that a request may be modified by the resolution
 * process, so this class keeps track of the original request.
 * 
 * DNSEvents are frequently created in response to the needs of another event.
 * The new event is chained to the old event forming a dependency chain.
 * 
 * @author davidb
 * @version $Revision: 286 $
 */
public class DNSEvent {
    /**
     * This is the current, mutable request -- this request will change based on
     * the current needs of a module.
     */
    private Message currentRequest;

    /**
     * This is the original, immutable request. This request must not be changed
     * after being set.
     */
    private Message originalRequest;

    /**
     * This is the normal response to the current request. It may be modified as
     * it travels through the chain, but only the most recent is relevant.
     */
    private SMessage response;

    /**
     * If event was created on behalf of another event, the "next" event is that
     * original event. That is, if this is not null, some other event is
     * (possibly) waiting on the completion of this one.
     */
    private DNSEvent forEvent;

    /**
     * State of the validation.
     */
    private ValEventState state;

    /**
     * This is the dependency depth of this event -- in other words, the length
     * of the "nextEvent" chain.
     */
    private int depth;

    /**
     * Create a request event.
     * 
     * @param request The initial request.
     */
    public DNSEvent(Message request) {
        this.originalRequest = request;
        this.currentRequest = (Message)request.clone();
    }

    /**
     * Create a local, dependent event.
     * 
     * @param request The initial request.
     * @param forEvent The dependent event.
     */
    public DNSEvent(Message request, DNSEvent forEvent) {
        this(request);

        this.forEvent = forEvent;
        this.depth = forEvent.getDepth() + 1;
    }

    /**
     * @return The current request.
     */
    public Message getRequest() {
        return this.currentRequest;
    }

    /**
     * @return The original request. Do not modify this!
     */
    public Message getOrigRequest() {
        return this.originalRequest;
    }

    /**
     * @return The "for" event. I.e., the event that is depending on this event.
     */
    public DNSEvent forEvent() {
        return this.forEvent;
    }

    /**
     * @return The response that has been attached to this event, or null if one
     *         hasn't been attached yet.
     */
    public SMessage getResponse() {
        return this.response;
    }

    /**
     * Attach a response to this event.
     * 
     * @param response The response message to attach. The must match the
     *            current request at time of attachment.
     */
    public void setResponse(SMessage response) {
        this.response = response;
    }

    /**
     * Fetch any attached per-module state for this event.
     * 
     * @return A state object for the module, or null if one wasn't attached.
     */
    public ValEventState getModuleState() {
        return this.state;
    }

    /**
     * Attach per-module state to this event.
     * 
     * @param state A state object.
     */
    public void setModuleState(ValEventState state) {
        this.state = state;
    }

    /**
     * @return The depth of this event. The depth is the events position in a
     *         dependency chain of events.
     */
    public int getDepth() {
        return this.depth;
    }

    /**
     * @return A string representation of the event, to be used in logging,
     *         perhaps.
     */
    public String toString() {
        Record q = this.currentRequest.getQuestion();
        return super.toString() + " " + q.getName() + "/" + Type.string(q.getType()) + "/" + DClass.string(q.getDClass());
    }
}
