#
#VID 5bae2ab4-0820-11e2-be5f-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 5bae2ab4-0820-11e2-be5f-00262d5ed8ee
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

include("revisions-lib.inc");
tag_insight = "The following package is affected: chromium

CVE-2012-2889
Cross-site scripting (XSS) vulnerability in Google Chrome before
22.0.1229.79 allows remote attackers to inject arbitrary web script or
HTML via vectors involving frames, aka 'Universal XSS (UXSS).'
CVE-2012-2886
Cross-site scripting (XSS) vulnerability in Google Chrome before
22.0.1229.79 allows remote attackers to inject arbitrary web script or
HTML via vectors related to the Google V8 bindings, aka 'Universal XSS
(UXSS).'
CVE-2012-2881
Google Chrome before 22.0.1229.79 does not properly handle plug-ins,
which allows remote attackers to cause a denial of service (DOM tree
corruption) or possibly have unspecified other impact via unknown
vectors.
CVE-2012-2876
Buffer overflow in the SSE2 optimization functionality in Google
Chrome before 22.0.1229.79 allows remote attackers to cause a denial
of service or possibly have unspecified other impact via unknown
vectors.
CVE-2012-2883
Skia, as used in Google Chrome before 22.0.1229.79, allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors that trigger an out-of-bounds write
operation, a different vulnerability than CVE-2012-2874.
CVE-2012-2887
Use-after-free vulnerability in Google Chrome before 22.0.1229.79
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving onclick events.
CVE-2012-2888
Use-after-free vulnerability in Google Chrome before 22.0.1229.79
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG text references.
CVE-2012-2894
Google Chrome before 22.0.1229.79 does not properly handle
graphics-context data structures, which allows remote attackers to
cause a denial of service (application crash) or possibly have
unspecified other impact via unknown vectors.
CVE-2012-2877
The extension system in Google Chrome before 22.0.1229.79 does not
properly handle modal dialogs, which allows remote attackers to cause
a denial of service (application crash) via unspecified vectors.
CVE-2012-2879
Google Chrome before 22.0.1229.79 allows remote attackers to cause a
denial of service (DOM topology corruption) via a crafted document.
CVE-2012-2884
Skia, as used in Google Chrome before 22.0.1229.79, allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.
CVE-2012-2874
Skia, as used in Google Chrome before 22.0.1229.79, allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors that trigger an out-of-bounds write
operation, a different vulnerability than CVE-2012-2883.
CVE-2012-2875
Multiple unspecified vulnerabilities in the PDF functionality in
Google Chrome before 22.0.1229.79 allow remote attackers to have an
unknown impact via a crafted document.
CVE-2012-2878
Use-after-free vulnerability in Google Chrome before 22.0.1229.79
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to plug-in handling.
CVE-2012-2880
Race condition in Google Chrome before 22.0.1229.79 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the plug-in paint buffer.
CVE-2012-2882
FFmpeg, as used in Google Chrome before 22.0.1229.79, does not
properly handle OGG containers, which allows remote attackers to cause
a denial of service or possibly have unspecified other impact via
unknown vectors, related to a 'wild pointer' issue.
CVE-2012-2885
Double free vulnerability in Google Chrome before 22.0.1229.79 allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to application exit.
CVE-2012-2890
Use-after-free vulnerability in the PDF functionality in Google Chrome
before 22.0.1229.79 allows remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted
document.
CVE-2012-2891
The IPC implementation in Google Chrome before 22.0.1229.79 allows
attackers to obtain potentially sensitive information about memory
addresses via unspecified vectors.
CVE-2012-2892
Unspecified vulnerability in Google Chrome before 22.0.1229.79 allows
remote attackers to bypass the pop-up blocker via unknown vectors.
CVE-2012-2893
Double free vulnerability in libxslt, as used in Google Chrome before
22.0.1229.79, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via vectors related to XSL
transforms.
CVE-2012-2895
The PDF functionality in Google Chrome before 22.0.1229.79 allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors that trigger out-of-bounds write
operations.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.nl/search/label/Stable%20updates
http://www.vuxml.org/freebsd/5bae2ab4-0820-11e2-be5f-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72445");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2889", "CVE-2012-2886", "CVE-2012-2881", "CVE-2012-2876", "CVE-2012-2883", "CVE-2012-2887", "CVE-2012-2888", "CVE-2012-2894", "CVE-2012-2877", "CVE-2012-2879", "CVE-2012-2884", "CVE-2012-2874", "CVE-2012-2875", "CVE-2012-2878", "CVE-2012-2880", "CVE-2012-2882", "CVE-2012-2885", "CVE-2012-2890", "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2893", "CVE-2012-2895");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-10-03 11:11:06 -0400 (Wed, 03 Oct 2012)");
 script_name("FreeBSD Ports: chromium");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
txt = "";
bver = portver(pkg:"chromium");
if(!isnull(bver) && revcomp(a:bver, b:"22.0.1229.79")<0) {
    txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99);
}
