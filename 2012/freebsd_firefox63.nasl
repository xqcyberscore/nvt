###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_firefox63.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 0a9e2b72-4cb7-11e1-9146-14dae9ebcf89
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70738");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-0442", "CVE-2012-0443", "CVE-2011-3670", "CVE-2012-0445", "CVE-2011-3659", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)");
  script_name("FreeBSD Ports: firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  firefox
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird

CVE-2012-0442
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 3.6.26 and 4.x through 9.0, Thunderbird before 3.1.18
and 5.0 through 9.0, and SeaMonkey before 2.7 allow remote attackers
to cause a denial of service (memory corruption and application crash)
or possibly execute arbitrary code via unknown vectors.

CVE-2012-0443
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 9.0, Thunderbird 5.0 through 9.0, and SeaMonkey
before 2.7 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.

CVE-2011-3670
Mozilla Firefox before 3.6.26 and 4.x through 6.0, Thunderbird before
3.1.18 and 5.0 through 6.0, and SeaMonkey before 2.4 do not properly
enforce the IPv6 literal address syntax, which allows remote attackers
to obtain sensitive information by making XMLHttpRequest calls through
a proxy and reading the error messages.

CVE-2012-0445
Mozilla Firefox 4.x through 9.0, Thunderbird 5.0 through 9.0, and
SeaMonkey before 2.7 allow remote attackers to bypass the HTML5
frame-navigation policy and replace arbitrary sub-frames by creating a
form submission target with a sub-frame's name attribute.

CVE-2011-3659
Use-after-free vulnerability in Mozilla Firefox before 3.6.26 and 4.x
through 9.0, Thunderbird before 3.1.18 and 5.0 through 9.0, and
SeaMonkey before 2.7 might allow remote attackers to execute arbitrary
code via vectors related to incorrect AttributeChildRemoved
notifications that affect access to removed nsDOMAttribute child
nodes.

CVE-2012-0446
Multiple cross-site scripting (XSS) vulnerabilities in Mozilla Firefox
4.x through 9.0, Thunderbird 5.0 through 9.0, and SeaMonkey before 2.7
allow remote attackers to inject arbitrary web script or HTML via a
(1) web page or (2) Firefox extension, related to improper enforcement
of XPConnect security restrictions for frame scripts that call
untrusted objects.

CVE-2012-0447
Mozilla Firefox 4.x through 9.0, Thunderbird 5.0 through 9.0, and
SeaMonkey before 2.7 do not properly initialize data for
image/vnd.microsoft.icon images, which allows remote attackers to
obtain potentially sensitive information by reading a PNG image that
was created through conversion from an ICO image.

CVE-2012-0449
Mozilla Firefox before 3.6.26 and 4.x through 9.0, Thunderbird before
3.1.18 and 5.0 through 9.0, and SeaMonkey before 2.7 allow remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly execute arbitrary code via a malformed
XSLT stylesheet that is embedded in a document.

CVE-2012-0450
Mozilla Firefox 4.x through 9.0 and SeaMonkey before 2.7 on Linux and
Mac OS X set weak permissions for Firefox Recovery Key.html, which
might allow local users to read a Firefox Sync key via standard
filesystem operations.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-02.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-03.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-04.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-05.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-06.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-07.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-08.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-09.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/0a9e2b72-4cb7-11e1-9146-14dae9ebcf89.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"10.0,1")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.6")>=0 && revcomp(a:bver, b:"3.6.26")<0) {
  txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0,1")<0) {
  txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.7")<0) {
  txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0")<0) {
  txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.7")<0) {
  txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"10.0")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.1")>0 && revcomp(a:bver, b:"3.1.18")<0) {
  txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}