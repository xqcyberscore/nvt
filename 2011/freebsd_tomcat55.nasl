#
#VID 553ec4ed-38d6-11e0-94b1-000c29ba66d2
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 553ec4ed-38d6-11e0-94b1-000c29ba66d2
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
   tomcat55
   tomcat6
   tomcat7

CVE-2011-0013
Multiple cross-site scripting (XSS) vulnerabilities in the HTML
Manager Interface in Apache Software Foundation Tomcat 7.0 before
7.0.6, 5.5 before 5.5.32, and 6.0 before 6.0.30 allow remote attackers
to inject arbitrary web script or HTML, as demonstrated via the
display-name tag.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.32
http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.30
http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.6
http://www.vuxml.org/freebsd/553ec4ed-38d6-11e0-94b1-000c29ba66d2.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68942");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2011-0013");
 script_name("FreeBSD Ports: tomcat55");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"tomcat55");
if(!isnull(bver) && revcomp(a:bver, b:"5.5.0")>0 && revcomp(a:bver, b:"5.5.32")<0) {
    txt += 'Package tomcat55 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tomcat6");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.0")>0 && revcomp(a:bver, b:"6.0.30")<0) {
    txt += 'Package tomcat6 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tomcat7");
if(!isnull(bver) && revcomp(a:bver, b:"7.0.0")>0 && revcomp(a:bver, b:"7.0.6")<0) {
    txt += 'Package tomcat7 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
