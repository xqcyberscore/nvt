#
#VID 6d21a287-fce0-11e0-a828-00235a5f2c9a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 6d21a287-fce0-11e0-a828-00235a5f2c9a
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
#

include("revisions-lib.inc");
tag_insight = "The following packages are affected:
   kdelibs
   rekonq

CVE-2011-3365
The KDE SSL Wrapper (KSSL) API in KDE SC 4.6.0 through 4.7.1, and
possibly earlier versions, does not use a certain font when rendering
certificate fields in a security dialog, which allows remote attackers
to spoof the common name (CN) of a certificate via rich text.

CVE-2011-3366
Rekonq 0.7.0 and earlier does not use a certain font when rendering
certificate fields in a security dialog, which allows remote attackers
to spoof the common name (CN) of a certificate via rich text.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.kde.org/info/security/advisory-20111003-1.txt
http://www.nth-dimension.org.uk/pub/NDSA20111003.txt.asc
http://www.vuxml.org/freebsd/6d21a287-fce0-11e0-a828-00235a5f2c9a.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70615");
 script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_cve_id("CVE-2011-3365", "CVE-2011-3366");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 9352 $");
 script_name("FreeBSD Ports: kdelibs");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"kdelibs");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>=0 && revcomp(a:bver, b:"4.7.2")<0) {
    txt += 'Package kdelibs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"rekonq");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.0")<0) {
    txt += 'Package rekonq version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
