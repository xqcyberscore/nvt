#
#VID 330106da-7406-11e1-a1d7-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 330106da-7406-11e1-a1d7-00262d5ed8ee
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

CVE-2011-3045
Integer signedness error in pngrutil.c in libpng before 1.4.10beta01,
as used in Google Chrome before 17.0.963.83 and other products, allows
remote attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a crafted PNG file, a different
vulnerability than CVE-2011-3026.
CVE-2011-3049
Google Chrome before 17.0.963.83 does not properly restrict the
extension web request API, which allows remote attackers to cause a
denial of service (disrupted system requests) via a crafted extension.
CVE-2011-3050
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 17.0.963.83 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the :first-letter pseudo-element.
CVE-2011-3051
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 17.0.963.83 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the cross-fade function.
CVE-2011-3052
The WebGL implementation in Google Chrome before 17.0.963.83 does not
properly handle CANVAS elements, which allows remote attackers to
cause a denial of service (memory corruption) or possibly have
unspecified other impact via unknown vectors.
CVE-2011-3053
Use-after-free vulnerability in Google Chrome before 17.0.963.83
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to block splitting.
CVE-2011-3054
The WebUI privilege implementation in Google Chrome before 17.0.963.83
does not properly perform isolation, which allows remote attackers to
bypass intended access restrictions via unspecified vectors.
CVE-2011-3055
The browser native UI in Google Chrome before 17.0.963.83 does not
require user confirmation before an unpacked extension installation,
which allows user-assisted remote attackers to have an unspecified
impact via a crafted extension.
CVE-2011-3056
Google Chrome before 17.0.963.83 allows remote attackers to bypass the
Same Origin Policy via vectors involving a 'magic iframe.'
CVE-2011-3057
Google V8, as used in Google Chrome before 17.0.963.83, allows remote
attackers to cause a denial of service via vectors that trigger an
invalid read operation.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.com/search/label/Stable%20updates
http://www.vuxml.org/freebsd/330106da-7406-11e1-a1d7-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71292");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-3045", "CVE-2011-3049", "CVE-2011-3050", "CVE-2011-3051", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054", "CVE-2011-3055", "CVE-2011-3056", "CVE-2011-3057");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"17.0.963.83")<0) {
    txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
