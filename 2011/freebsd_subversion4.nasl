#
#VID e27a1af3-8d21-11e0-a45d-001e8c75030d
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e27a1af3-8d21-11e0-a45d-001e8c75030d
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
   subversion
   subversion-freebsd

CVE-2011-1752
The mod_dav_svn module for the Apache HTTP Server, as distributed in
Apache Subversion before 1.6.17, allows remote attackers to cause a
denial of service (NULL pointer dereference and daemon crash) via a
request for a baselined WebDAV resource, as exploited in the wild in
May 2011.
CVE-2011-1783
The mod_dav_svn module for the Apache HTTP Server, as distributed in
Apache Subversion 1.5.x and 1.6.x before 1.6.17, when the SVNPathAuthz
short_circuit option is enabled, allows remote attackers to cause a
denial of service (infinite loop and memory consumption) in
opportunistic circumstances by requesting data.
CVE-2011-1921
The mod_dav_svn module for the Apache HTTP Server, as distributed in
Apache Subversion 1.5.x and 1.6.x before 1.6.17, when the SVNPathAuthz
short_circuit option is disabled, does not properly enforce
permissions for files that had been publicly readable in the past,
which allows remote attackers to obtain sensitive information via a
replay REPORT operation.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69755");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");
 script_name("FreeBSD Ports: subversion");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
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
bver = portver(pkg:"subversion");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.17")<0) {
    txt += 'Package subversion version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"subversion-freebsd");
if(!isnull(bver) && revcomp(a:bver, b:"1.6.17")<0) {
    txt += 'Package subversion-freebsd version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
