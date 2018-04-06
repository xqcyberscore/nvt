#
#VID 9f971cea-03f5-11e0-bf50-001a926c7637
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 9f971cea-03f5-11e0-bf50-001a926c7637
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
tag_insight = "The following package is affected: krb5

CVE-2010-1324
MIT Kerberos 5 (aka krb5) 1.7.x and 1.8.x through 1.8.3 does not
properly determine the acceptability of checksums, which might allow
remote attackers to forge GSS tokens, gain privileges, or have
unspecified other impact via (1) an unkeyed checksum, (2) an unkeyed
PAC checksum, or (3) a KrbFastArmoredReq checksum based on an RC4 key.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68693");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2010-1324");
 script_bugtraq_id(45116);
 script_name("FreeBSD Ports: krb5");



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
 script_xref(name : "URL" , value : "http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2010-007.txt");
 script_xref(name : "URL" , value : "http://www.vuxml.org/freebsd/9f971cea-03f5-11e0-bf50-001a926c7637.html");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"krb5");
if(!isnull(bver) && revcomp(a:bver, b:"1.7.0")>=0 && revcomp(a:bver, b:"1.8.0")<0) {
    txt += 'Package krb5 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
