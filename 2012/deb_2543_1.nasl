# OpenVAS Vulnerability Test
# $Id: deb_2543_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2543-1 (xen-qemu-dm-4.0)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Multiple vulnerabilities have been discovered in xen-qemu-dm-4.0, the Xen
Qemu Device Model virtual machine hardware emulator. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-3515:

The device model for HVM domains does not properly handle VT100
escape sequences when emulating certain devices with a virtual
console backend. An attacker within a guest with access to the
vulnerable virtual console could overwrite memory of the device
model and escalate privileges to that of the device model process.

CVE-2012-4411:

The qemu monitor was enabled by default, allowing administrators of
a guest to access resources of the host, possibly escalate privileges
or access resources belonging to another guest.

For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-2+squeeze2.

The testing distribution (wheezy), and the unstable distribution (sid),
no longer contain this package.

We recommend that you upgrade your xen-qemu-dm-4.0 packages.";
tag_summary = "The remote host is missing an update to xen-qemu-dm-4.0
announced via advisory DSA 2543-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202543-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72172");
 script_cve_id("CVE-2012-3515", "CVE-2012-4411");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-09-15 04:24:00 -0400 (Sat, 15 Sep 2012)");
 script_name("Debian Security Advisory DSA 2543-1 (xen-qemu-dm-4.0)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
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

include("pkg-lib-deb.inc");
res = "";
report = "";
if((res = isdpkgvuln(pkg:"xen-qemu-dm-4.0", ver:"4.0.1-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
