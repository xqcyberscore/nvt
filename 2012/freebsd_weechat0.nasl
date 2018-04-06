#
#VID e02c572f-2af0-11e2-bb44-003067b2972c
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e02c572f-2af0-11e2-bb44-003067b2972c
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
   weechat
   weechat-devel

CVE-2012-5854
Heap-based buffer overflow in WeeChat 0.3.6 through 0.3.9 allows
remote attackers to cause a denial of service (crash or hang) and
possibly execute arbitrary code via crafted IRC colors that are not
properly decoded.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://weechat.org/security/
https://savannah.nongnu.org/bugs/?37704
http://www.vuxml.org/freebsd/e02c572f-2af0-11e2-bb44-003067b2972c.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72604");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-5854");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
 script_name("FreeBSD Ports: weechat");


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
bver = portver(pkg:"weechat");
if(!isnull(bver) && revcomp(a:bver, b:"0.3.6")>=0 && revcomp(a:bver, b:"0.3.9.1")<0) {
    txt += "Package weechat version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"weechat-devel");
if(!isnull(bver) && revcomp(a:bver, b:"20110614")>=0 && revcomp(a:bver, b:"20121110")<0) {
    txt += "Package weechat-devel version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99);
}
