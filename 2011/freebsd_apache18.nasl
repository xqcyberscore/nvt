#
#VID 7f6108d2-cea8-11e0-9d58-0800279895ea
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 7f6108d2-cea8-11e0-9d58-0800279895ea
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
   apache
   apache-event
   apache-itk
   apache-peruser
   apache-worker

CVE-2011-3192
The byterange filter in the Apache HTTP Server 1.3.x, 2.0.x through
2.0.64, and 2.2.x through 2.2.19 allows remote attackers to cause a
denial of service (memory and CPU consumption) via a Range header that
expresses multiple overlapping ranges, as exploited in the wild in
August 2011, a different vulnerability than CVE-2007-0086.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://people.apache.org/~dirkx/CVE-2011-3192.txt
https://svn.apache.org/viewvc?view=revision&revision=1161534
https://svn.apache.org/viewvc?view=revision&revision=1162874
http://www.vuxml.org/freebsd/7f6108d2-cea8-11e0-9d58-0800279895ea.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70253");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-3192");
 script_name("FreeBSD Ports: apache, apache-event, apache-itk, apache-peruser, apache-worker");



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
bver = portver(pkg:"apache");
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.2.20")<0) {
    txt += 'Package apache version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache-event");
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.2.20")<0) {
    txt += 'Package apache-event version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache-itk");
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.2.20")<0) {
    txt += 'Package apache-itk version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache-peruser");
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.2.20")<0) {
    txt += 'Package apache-peruser version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"apache-worker");
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.2.20")<0) {
    txt += 'Package apache-worker version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
