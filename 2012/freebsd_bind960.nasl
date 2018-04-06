#
#VID 90cc1494-10ac-11e1-b3ec-0024e830109b
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 90cc1494-10ac-11e1-b3ec-0024e830109b
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
   bind96
   bind97
   bind98

CVE-2011-4313
query.c in ISC BIND 9.0.x through 9.6.x, 9.4-ESV through 9.4-ESV-R5,
9.6-ESV through 9.6-ESV-R5, 9.7.0 through 9.7.4, 9.8.0 through 9.8.1,
and 9.9.0a1 through 9.9.0b1 allows remote attackers to cause a denial
of service (assertion failure and named exit) via unknown vectors
related to recursive DNS queries, error logging, and the caching of an
invalid record by the resolver.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";

tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70599");
 script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_cve_id("CVE-2011-4313");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 9352 $");
 script_name("FreeBSD Ports: bind96");

 script_xref(name:"URL" , value:"https://www.isc.org/software/bind/advisories/cve-2011-4313");
 script_xref(name:"URL" , value:"http://www.vuxml.org/freebsd/90cc1494-10ac-11e1-b3ec-0024e830109b.html");


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
bver = portver(pkg:"bind96");
if(!isnull(bver) && revcomp(a:bver, b:"9.6.3.1.ESV.R5.1")<0) {
    txt += 'Package bind96 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"bind97");
if(!isnull(bver) && revcomp(a:bver, b:"9.7.4.1")<0) {
    txt += 'Package bind97 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"bind98");
if(!isnull(bver) && revcomp(a:bver, b:"9.8.1.1")<0) {
    txt += 'Package bind98 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
