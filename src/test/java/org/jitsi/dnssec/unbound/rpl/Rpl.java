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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.jitsi.dnssec.SRRset;
import org.xbill.DNS.Message;

public class Rpl {
  public List<SRRset> trustAnchors = new ArrayList<>(1);
  public Instant date;
  public String scenario;
  public List<Message> replays;
  public Map<Integer, Check> checks;
  public TreeMap<Integer, Integer> nsec3iterations;
  public String digestPreference;
  public boolean hardenAlgoDowngrade;
  public boolean enableSha1;
  public boolean enableDsa;
}
