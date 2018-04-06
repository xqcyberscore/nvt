#
#VID 373e412e-f748-11df-96cd-0015f2db7bde
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 373e412e-f748-11df-96cd-0015f2db7bde
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: openttd

CVE-2010-4168
Multiple use-after-free vulnerabilities in OpenTTD 1.0.x before 1.0.5
allow (1) remote attackers to cause a denial of service (invalid write
and daemon crash) by abruptly disconnecting during transmission of the
map from the server, related to network/network_server.cpp; (2) remote
attackers to cause a denial of service (invalid read and daemon crash)
by abruptly disconnecting, related to network/network_server.cpp; and
(3) remote servers to cause a denial of service (invalid read and
application crash) by forcing a disconnection during the join process,
related to network/network.cpp.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://security.openttd.org/en/CVE-2010-4168
http://www.vuxml.org/freebsd/373e412e-f748-11df-96cd-0015f2db7bde.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68700");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2010-4168");
 script_name("FreeBSD Ports: openttd");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"openttd");
if(!isnull(bver) && revcomp(a:bver, b:"1.0.0")>=0 && revcomp(a:bver, b:"1.0.5")<0) {
    txt += 'Package openttd version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
