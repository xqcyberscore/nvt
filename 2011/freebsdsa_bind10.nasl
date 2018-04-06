#
#ADV FreeBSD-SA-11:02.bind.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-11:02.bind.asc
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

tag_insight = "BIND 9 is an implementation of the Domain Name System (DNS) protocols.
The named(8) daemon is an Internet Domain Name Server.

DNS Security Extensions (DNSSEC) provides data integrity, origin
authentication and authenticated denial of existence to resolvers.

Very large RRSIG RRsets included in a negative response can trigger
an assertion failure that will crash named(8) due to an off-by-one error
in a buffer size check.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:02.bind.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-11:02.bind.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69771");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_cve_id("CVE-2011-1910");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-11:02.bind.asc)");



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
if(patchlevelcmp(rel:"7.3", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.4", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.1", patchlevel:"4")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.2", patchlevel:"2")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
