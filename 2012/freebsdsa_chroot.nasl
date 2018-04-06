#
#ADV FreeBSD-SA-11:07.chroot.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-11:07.chroot.asc
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

tag_insight = "Chroot is an operation that changes the apparent root directory for the
current process and its children.  The chroot(2) system call is widely
used in many applications as a measure of limiting a process's access to
the file system, as part of implementing privilege separation.

The nsdispatch(3) API implementation has a feature to reload its
configuration on demand.  This feature may also load shared libraries
and run code provided by the library when requested by the configuration
file.

The nsdispatch(3) API has no mechanism to alert it to whether it is
operating within a chroot environment in which the standard paths for
configuration files and shared libraries may be untrustworthy.

The FreeBSD ftpd(8) daemon can be configured to use chroot(2), and
also uses the nsdispatch(3) API.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:07.chroot.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-11:07.chroot.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70762");
 script_version("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-11:07.chroot.asc)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:37:01 -0500 (Sun, 12 Feb 2012)");


 script_tag(name:"qod_type", value:"package");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"7.4", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"9")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.2", patchlevel:"5")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.1", patchlevel:"7")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
