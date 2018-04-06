# OpenVAS Vulnerability Test
# $Id: deb_2426_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2426-1 (gimp)
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
tag_insight = "Several vulnerabilities have been identified in GIMP, the GNU Image
Manipulation Program.

CVE-2010-4540
Stack-based buffer overflow in the load_preset_response
function in plug-ins/lighting/lighting-ui.c in the LIGHTING
EFFECTS > LIGHT plugin allows user-assisted remote attackers
to cause a denial of service (application crash) or possibly
execute arbitrary code via a long Position field in a plugin
configuration file.

CVE-2010-4541
Stack-based buffer overflow in the loadit function in
plug-ins/common/sphere-designer.c in the SPHERE DESIGNER
plugin allows user-assisted remote attackers to cause a denial
of service (application crash) or possibly execute arbitrary
code via a long Number of lights field in a plugin
configuration file.

CVE-2010-4542
Stack-based buffer overflow in the gfig_read_parameter_gimp_rgb
function in in the GFIG plugin allows user-assisted remote
attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a long Foreground field in a
plugin configuration file.

CVE-2010-4543
Heap-based buffer overflow in the read_channel_data function in
file-psp.c in the Paint Shop Pro (PSP) plugin allows remote
attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a PSP_COMP_RLE (aka RLE
compression) image file that begins a long run count at the end
of the image.

CVE-2011-1782
The correction for CVE-2010-4543 was incomplete.

CVE-2011-2896
The LZW decompressor in the LZWReadByte function in
plug-ins/common/file-gif-load.c does not properly handle code
words that are absent from the decompression table when
encountered, which allows remote attackers to trigger an
infinite loop or a heap-based buffer overflow, and possibly
execute arbitrary code, via a crafted compressed stream.


For the stable distribution (squeeze), these problems have been fixed in
version 2.6.10-1+squeeze3.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 2.6.11-5.

We recommend that you upgrade your gimp packages.";
tag_summary = "The remote host is missing an update to gimp
announced via advisory DSA 2426-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202426-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71154");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543", "CVE-2011-1782", "CVE-2011-2896");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:33:30 -0400 (Mon, 12 Mar 2012)");
 script_name("Debian Security Advisory DSA 2426-1 (gimp)");



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
if((res = isdpkgvuln(pkg:"gimp", ver:"2.6.10-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"gimp-data", ver:"2.6.10-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"gimp-dbg", ver:"2.6.10-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.6.10-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.6.10-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.6.10-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"gimp", ver:"2.6.12-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"gimp-data", ver:"2.6.12-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"gimp-dbg", ver:"2.6.12-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.6.12-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.6.12-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.6.12-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
