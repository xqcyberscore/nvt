# OpenVAS Vulnerability Test
# $Id: deb_2471_1.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2471-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_affected  = "ffmpeg on Debian Linux";
tag_insight   = "This package contains the ffplay multimedia player, the ffserver streaming
server and the ffmpeg audio and video encoder. They support most existing
file formats (AVI, MPEG, OGG, Matroska, ASF...) and encoding formats (MPEG,
DivX, MPEG4, AC3, DV...).";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 4:0.5.8-1.

For the unstable distribution (sid), this problem has been fixed in
version 6:0.8.2-1 of libav.

We recommend that you upgrade your ffmpeg packages.";
tag_summary   = "Several vulnerabilities have been discovered in FFmpeg, a multimedia
player, server and encoder. Multiple input validations in the decoders/
demuxers for Westwood Studios VQA, Apple MJPEG-B, Theora, Matroska,
Vorbis, Sony ATRAC3, DV, NSV, files could lead to the execution of
arbitrary code.

These issues were discovered by Aki Helin, Mateusz Jurczyk, Gynvael
Coldwind, and Michael Niedermayer.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892471");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2011-3893", "CVE-2011-3895", "CVE-2011-3936", "CVE-2012-0947", "CVE-2011-3892", "CVE-2011-3929", "CVE-2011-3940", "CVE-2011-3947", "CVE-2012-0853");
    script_name("Debian Security Advisory DSA 2471-1 (ffmpeg - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2471.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavfilter0", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat52", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil49", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale0", ver:"4:0.5.8-1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
