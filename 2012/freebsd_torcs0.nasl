#
#VID ba51c2f7-5b43-11e1-8288-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ba51c2f7-5b43-11e1-8288-00262d5ed8ee
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
   torcs
   plib

CVE-2011-4620
Buffer overflow in the ulSetError function in util/ulError.cxx in PLIB
1.8.5, as used in TORCS 1.3.1 and other products, allows user-assisted
remote attackers to execute arbitrary code via vectors involving a
long error message, as demonstrated by a crafted acc file for TORCS.
NOTE: some of these details are obtained from third party information.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/47297/
http://torcs.sourceforge.net/index.php?name=News&file=article&sid=79
http://www.vuxml.org/freebsd/ba51c2f7-5b43-11e1-8288-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71167");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-4620");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
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
vuln = 0;
txt = "";
bver = portver(pkg:"torcs");
if(!isnull(bver) && revcomp(a:bver, b:"1.3.3")<0) {
    txt += "Package torcs version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"plib");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.5_3")<=0) {
    txt += "Package plib version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
