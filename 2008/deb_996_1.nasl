# OpenVAS Vulnerability Test
# $Id: deb_996_1.nasl 4053 2016-09-14 05:26:09Z teissa $
# Description: Auto-generated from advisory DSA 996-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_solution = "For the stable distribution (sarge) this problem has been fixed in
version 2.12-1sarge1.

For the unstable distribution (sid) this problem has been fixed in
version 2.17-1.

We recommend that you upgrade your libcrypt-cbc-perl package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20996-1";
tag_summary = "The remote host is missing an update to libcrypt-cbc-perl
announced via advisory DSA 996-1.

Lincoln Stein discovered that the Perl Crypt::CBC module produces weak
ciphertext when used with block encryption algorithms with blocksize >
8 bytes.

The old stable distribution (woody) does not contain a Crypt::CBC module.";


if(description)
{
 script_id(56403);
 script_version("$Revision: 4053 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-14 07:26:09 +0200 (Wed, 14 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(16802);
 script_cve_id("CVE-2006-0898");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 996-1 (libcrypt-cbc-perl)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"libcrypt-cbc-perl", ver:"2.12-1sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
