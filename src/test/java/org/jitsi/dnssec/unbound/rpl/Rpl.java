/*
 * dnssecjava - a DNSSEC validating stub resolver for Java
 * Copyright (c) 2013-2015 Ingo Bauersachs
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */

package org.jitsi.dnssec.unbound.rpl;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.jitsi.dnssec.SRRset;
import org.joda.time.DateTime;
import org.xbill.DNS.Message;

public class Rpl {
    public List<SRRset> trustAnchors = new ArrayList<SRRset>(1);
    public DateTime date;
    public String scenario;
    public List<Message> replays;
    public Map<Integer, Check> checks;
    public TreeMap<Integer, Integer> nsec3iterations;
    public String digestPreference;
    public boolean hardenAlgoDowngrade;
}
