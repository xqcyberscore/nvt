#
#VID e7fd27b2-3ae9-11e1-8b5c-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e7fd27b2-3ae9-11e1-8b5c-00262d5ed8ee
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
tag_insight = "The following package is affected: torcs

CVE-2010-3384
The (1) torcs, (2) nfsperf, (3) accc, (4) texmapper, (5) trackgen, and
(6) nfs2ac scripts in TORCS 1.3.1 place a zero-length directory name
in the LD_LIBRARY_PATH, which allows local users to gain privileges
via a Trojan horse shared library in the current working directory.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://torcs.sourceforge.net/index.php?name=News&file=article&sid=77
http://sourceforge.net/tracker/index.php?func=detail&aid=3089384&group_id=3777&atid=103777
http://www.vuxml.org/freebsd/e7fd27b2-3ae9-11e1-8b5c-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70760");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-3384");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: torcs");



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
txt = "";
bver = portver(pkg:"torcs");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.2")<0) {
    txt += 'Package torcs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
