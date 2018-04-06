#
#VID ce84e136-e2f6-11e1-a8ca-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ce84e136-e2f6-11e1-a8ca-00262d5ed8ee
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

CVE-2012-2846
Google Chrome before 21.0.1180.57 on Linux does not properly isolate
renderer processes, which allows remote attackers to cause a denial of
service (cross-process interference) via unspecified vectors.
CVE-2012-2847
Google Chrome before 21.0.1180.57 on Mac OS X and Linux, and before
21.0.1180.60 on Windows and Chrome Frame, does not request user
confirmation before continuing a large series of downloads, which
allows user-assisted remote attackers to cause a denial of service
(resource consumption) via a crafted web site.
CVE-2012-2848
The drag-and-drop implementation in Google Chrome before 21.0.1180.57
on Mac OS X and Linux, and before 21.0.1180.60 on Windows and Chrome
Frame, allows user-assisted remote attackers to bypass intended file
access restrictions via a crafted web site.
CVE-2012-2849
Off-by-one error in the GIF decoder in Google Chrome before
21.0.1180.57 on Mac OS X and Linux, and before 21.0.1180.60 on Windows
and Chrome Frame, allows remote attackers to cause a denial of service
(out-of-bounds read) via a crafted image.
CVE-2012-2850
Multiple unspecified vulnerabilities in the PDF functionality in
Google Chrome before 21.0.1180.57 on Mac OS X and Linux, and before
21.0.1180.60 on Windows and Chrome Frame, allow remote attackers to
have an unknown impact via a crafted document.
CVE-2012-2851
Multiple integer overflows in the PDF functionality in Google Chrome
before 21.0.1180.57 on Mac OS X and Linux, and before 21.0.1180.60 on
Windows and Chrome Frame, allow remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted
document.
CVE-2012-2852
The PDF functionality in Google Chrome before 21.0.1180.57 on Mac OS X
and Linux, and before 21.0.1180.60 on Windows and Chrome Frame, does
not properly handle object linkage, which allows remote attackers to
cause a denial of service (use-after-free) or possibly have
unspecified other impact via a crafted document.
CVE-2012-2853
The webRequest API in Google Chrome before 21.0.1180.57 on Mac OS X
and Linux, and before 21.0.1180.60 on Windows and Chrome Frame, does
not properly interact with the Chrome Web Store, which allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via a crafted web site.
CVE-2012-2854
Google Chrome before 21.0.1180.57 on Mac OS X and Linux, and before
21.0.1180.60 on Windows and Chrome Frame, allows remote attackers to
obtain potentially sensitive information about pointer values by
leveraging access to a WebUI renderer process.
CVE-2012-2855
Use-after-free vulnerability in the PDF functionality in Google Chrome
before 21.0.1180.57 on Mac OS X and Linux, and before 21.0.1180.60 on
Windows and Chrome Frame, allows remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted
document.
CVE-2012-2856
The PDF functionality in Google Chrome before 21.0.1180.57 on Mac OS X
and Linux, and before 21.0.1180.60 on Windows and Chrome Frame, allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors that trigger out-of-bounds write
operations.
CVE-2012-2857
Use-after-free vulnerability in the Cascading Style Sheets (CSS) DOM
implementation in Google Chrome before 21.0.1180.57 on Mac OS X and
Linux, and before 21.0.1180.60 on Windows and Chrome Frame, allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted document.
CVE-2012-2858
Buffer overflow in the WebP decoder in Google Chrome before
21.0.1180.57 on Mac OS X and Linux, and before 21.0.1180.60 on Windows
and Chrome Frame, allows remote attackers to cause a denial of service
or possibly have unspecified other impact via a crafted WebP image.
CVE-2012-2859
Google Chrome before 21.0.1180.57 on Linux does not properly handle
tabs, which allows remote attackers to execute arbitrary code or cause
a denial of service (application crash) via unspecified vectors.
CVE-2012-2860
The date-picker implementation in Google Chrome before 21.0.1180.57 on
Mac OS X and Linux, and before 21.0.1180.60 on Windows and Chrome
Frame, allows user-assisted remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted web
site.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.com/search/label/Stable%20updates
http://www.vuxml.org/freebsd/ce84e136-e2f6-11e1-a8ca-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71505");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2846", "CVE-2012-2847", "CVE-2012-2848", "CVE-2012-2849", "CVE-2012-2850", "CVE-2012-2851", "CVE-2012-2852", "CVE-2012-2853", "CVE-2012-2854", "CVE-2012-2855", "CVE-2012-2856", "CVE-2012-2857", "CVE-2012-2858", "CVE-2012-2859", "CVE-2012-2860");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"21.0.1180.60")<0) {
    txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
