#<center>Work in Progress! Do NOT yet rely on the results!</center>
<hr/>

dnssecjava
==========
A DNSSEC validating stub resolver for Java.

History
-------
This project is based on the work of the Unbound Java prototype
from 2005/2006.

Current State
-------------
The Unbound prototype was stripped from all unnecessary parts, heavily
modified and bugfixed. Unit tests are currently covering little over 80%
of the code, so there is still a lot of work to do. See the corresponding
TODO-file for details.

Usage
-----
The project is intended to be used as a `Resolver` for
[DNSJAVA](www.xbill.org/dnsjava/). Validated responses contain the DNS
`AD`-flag, while responses that failed validation return the
`SERVFAIL`-RCode.

Build
-----
Ideally just run `mvn package`, but see the TODO why this currently
doesn't work. Building is still possible by importing the project into
Eclipse, adding a library reference to the patched DNSJAVA.
