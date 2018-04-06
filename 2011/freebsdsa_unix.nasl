#
#ADV FreeBSD-SA-11:05.unix.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-11:05.unix.asc
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

tag_insight = "UNIX-domain sockets, also known as local sockets, are a mechanism for
interprocess communication.  They are similar to Internet sockets (and
utilize the same system calls) but instead of relying on IP addresses
and port numbers, UNIX-domain sockets have addresses in the local file
system address space.

When a UNIX-domain socket is attached to a location using the bind(2)
system call, the length of the provided path is not validated.  Later,
when this address was returned via other system calls, it is copied into
a fixed-length buffer.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:05.unix.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-11:05.unix.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70416");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-11:05.unix.asc)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");



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
if(patchlevelcmp(rel:"7.4", patchlevel:"3")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"7")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.2", patchlevel:"3")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.1", patchlevel:"5")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
