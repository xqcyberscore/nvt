# OpenVAS Vulnerability Test
# $Id: deb_2404_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2404-1 (xen-qemu-dm-4.0)
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
tag_insight = "Nicolae Mogoraenu discovered a heap overflow in the emulated e1000e
network interface card of QEMU, which is used in the xen-qemu-dm-4.0
packages.  This vulnerability might enable to malicious guest systems
to crash the host system or escalate their privileges.

The old stable distribution (lenny) does not contain the
xen-qemu-dm-4.0 package.

For the stable distribution (squeeze), this problem has been fixed in
version 4.0.1-2+squeeze1.

The testing distribution (wheezy) and the unstable distribution (sid)
will be fixed soon.

Further information about Debian Security Advisories, how to apply
these updates to your system and frequently asked questions can be
found at: http://www.debian.org/security/";
tag_summary = "The remote host is missing an update to xen-qemu-dm-4.0
announced via advisory DSA 2404-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202404-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70723");
 script_tag(name:"cvss_base", value:"7.4");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2012-0029");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 06:39:51 -0500 (Sun, 12 Feb 2012)");
 script_name("Debian Security Advisory DSA 2404-1 (xen-qemu-dm-4.0)");


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
if((res = isdpkgvuln(pkg:"xen-qemu-dm-4.0", ver:"4.0.1-2+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
