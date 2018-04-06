# OpenVAS Vulnerability Test
# $Id: deb_2165_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2165-1 (ffmpeg-debian)
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
tag_insight = "Several vulnerabilities have been discovered in FFmpeg coders, which are used by
by MPlayer and other applications.


CVE-2010-3429

Cesar Bernardini and Felipe Andres Manzano reported an arbitrary offset
dereference vulnerability in the libavcodec, in particular in the flic file
format parser. A specific flic file may exploit this vulnerability and execute
arbitrary code. Mplayer is also affected by this problem, as well as other
software that use this library.


CVE-2010-4704

Greg Maxwell discovered an integer overflow the Vorbis decoder in FFmpeg. A
specific ogg file may exploit this vulnerability and execute arbitrary code.


CVE-2010-4705

A potential integer overflow has been discovered in the Vorbis decoder in
FFmpeg.


This upload also fixes an incomplete patch from DSA-2000-1. Michael Gilbert
noticed that there was remaining vulnerabilities, which  may cause a denial of
service and potentially execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.svn20080206-18+lenny3.

We recommend that you upgrade your ffmpeg-debian packages.";
tag_summary = "The remote host is missing an update to ffmpeg-debian
announced via advisory DSA 2165-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202165-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68976");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-3429", "CVE-2010-4704", "CVE-2010-4705");
 script_name("Debian Security Advisory DSA 2165-1 (ffmpeg-debian)");



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
if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavcodec51", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavformat52", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libavutil49", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libswscale0", ver:"0.svn20080206-18+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
