#
#ADV FreeBSD-SA-11:01.mountd.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-11:01.mountd.asc
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

tag_insight = "The mountd(8) daemon services NFS mount requests from other client
machines.  When mountd is started, it loads the export host addresses
and options into the kernel using the mount(2) system call.

While parsing the exports(5) table, a network mask in the form of
-network=netname/prefixlength results in an incorrect network mask
being computed if the prefix length is not a multiple of 8.

For example, specifying the ACL for an export as -network 192.0.2.0/23
would result in a netmask of 255.255.127.0 being used instead of the
correct netmask of 255.255.254.0.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:01.mountd.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-11:01.mountd.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69603");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-1739");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-11:01.mountd.asc)");



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
if(patchlevelcmp(rel:"7.3", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.4", patchlevel:"1")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.1", patchlevel:"3")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.2", patchlevel:"1")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
