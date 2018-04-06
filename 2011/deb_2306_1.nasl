# OpenVAS Vulnerability Test
# $Id: deb_2306_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2306-1 (ffmpeg)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in ffmpeg, a multimedia player,
server and encoder.
The Common Vulnerabilities and Exposures project identifies the following
problems:


CVE-2010-3908

FFmpeg before 0.5.4, allows remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute arbitrary code
via a malformed WMV file.


CVE-2010-4704

libavcodec/vorbis_dec.c in the Vorbis decoder in FFmpeg allows remote
attackers to cause a denial of service (application crash) via a crafted
.ogg file, related to the vorbis_floor0_decode function.


CVE-2011-0480

Multiple buffer overflows in vorbis_dec.c in the Vorbis decoder in FFmpeg
allow remote attackers to cause a denial of service (memory corruption and
application crash) or possibly have unspecified other impact via a crafted
WebM file, related to buffers for the channel floor and the channel residue.


CVE-2011-0722

FFmpeg allows remote attackers to cause a denial of service (heap memory
corruption and application crash) or possibly execute arbitrary code via a
malformed RealMedia file.


For the stable distribution (squeeze), this problem has been fixed in
version 4:0.5.4-1.

Security support for ffmpeg has been discontinued for the oldstable
distribution (lenny).
The current version in oldstable is not supported by upstream anymore
and is affected by several security issues. Backporting fixes for these
and any future issues has become unfeasible and therefore we need to
drop our security support for the version in oldstable.


We recommend that you upgrade your ffmpeg packages.";
tag_summary = "The remote host is missing an update to ffmpeg
announced via advisory DSA 2306-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202306-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70239");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-3908", "CVE-2010-4704", "CVE-2011-0480", "CVE-2011-0722", "CVE-2011-0723");
 script_name("Debian Security Advisory DSA 2306-1 (ffmpeg)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavfilter0", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil49", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale0", ver:"4:0.5.4-1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
