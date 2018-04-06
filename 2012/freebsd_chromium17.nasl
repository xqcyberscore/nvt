#
#VID ff922811-c096-11e1-b0f4-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ff922811-c096-11e1-b0f4-00262d5ed8ee
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

CVE-2012-2815
Google Chrome before 20.0.1132.43 allows remote attackers to obtain
potentially sensitive information from a fragment identifier by
leveraging access to an IFRAME element associated with a different
domain.
CVE-2012-2817
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to tables that have
sections.
CVE-2012-2818
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the layout of
documents that use the Cascading Style Sheets (CSS) counters feature.
CVE-2012-2819
The texSubImage2D implementation in the WebGL subsystem in Google
Chrome before 20.0.1132.43 does not properly handle uploads to
floating-point textures, which allows remote attackers to cause a
denial of service (assertion failure and application crash) or
possibly have unspecified other impact via a crafted web page, as
demonstrated by certain WebGL performance tests, aka rdar problem
11520387.
CVE-2012-2820
Google Chrome before 20.0.1132.43 does not properly implement SVG
filters, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2012-2821
The autofill implementation in Google Chrome before 20.0.1132.43 does
not properly display text, which has unspecified impact and remote
attack vectors.
CVE-2012-2822
The PDF functionality in Google Chrome before 20.0.1132.43 allows
remote attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.
CVE-2012-2823
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG resources.
CVE-2012-2824
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG painting.
CVE-2012-2826
Google Chrome before 20.0.1132.43 does not properly implement texture
conversion, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2012-2827
Use-after-free vulnerability in the UI in Google Chrome before
20.0.1132.43 on Mac OS X allows attackers to cause a denial of service
or possibly have unspecified other impact via unknown vectors.
CVE-2012-2828
Multiple integer overflows in the PDF functionality in Google Chrome
before 20.0.1132.43 allow remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted
document.
CVE-2012-2829
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 20.0.1132.43 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the :first-letter pseudo-element.
CVE-2012-2830
Google Chrome before 20.0.1132.43 does not properly set array values,
which allows remote attackers to cause a denial of service (incorrect
pointer use) or possibly have unspecified other impact via unknown
vectors.
CVE-2012-2831
Use-after-free vulnerability in Google Chrome before 20.0.1132.43
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG references.
CVE-2012-2832
The image-codec implementation in the PDF functionality in Google
Chrome before 20.0.1132.43 does not initialize an unspecified pointer,
which allows remote attackers to cause a denial of service or possibly
have unknown other impact via a crafted document.
CVE-2012-2833
Buffer overflow in the JS API in the PDF functionality in Google
Chrome before 20.0.1132.43 allows remote attackers to cause a denial
of service or possibly have unspecified other impact via unknown
vectors.
CVE-2012-2834
Integer overflow in Google Chrome before 20.0.1132.43 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via crafted data in the Matroska container format.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.com/search/label/Stable%20updates
http://www.vuxml.org/freebsd/ff922811-c096-11e1-b0f4-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71529");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-2815", "CVE-2012-2817", "CVE-2012-2818", "CVE-2012-2819", "CVE-2012-2820", "CVE-2012-2821", "CVE-2012-2822", "CVE-2012-2823", "CVE-2012-2824", "CVE-2012-2826", "CVE-2012-2827", "CVE-2012-2828", "CVE-2012-2829", "CVE-2012-2830", "CVE-2012-2831", "CVE-2012-2832", "CVE-2012-2833", "CVE-2012-2834");
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
if(!isnull(bver) && revcomp(a:bver, b:"20.0.1132.43")<0) {
    txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
