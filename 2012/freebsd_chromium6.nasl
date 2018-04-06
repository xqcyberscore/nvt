#
#VID 99aef698-66ed-11e1-8288-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 99aef698-66ed-11e1-8288-00262d5ed8ee
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

CVE-2011-3031
Use-after-free vulnerability in the element wrapper in Google V8, as
used in Google Chrome before 17.0.963.65, allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via unknown vectors.

CVE-2011-3032
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of SVG
values.

CVE-2011-3033
Buffer overflow in Skia, as used in Google Chrome before 17.0.963.65,
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors.

CVE-2011-3034
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving an SVG document.

CVE-2011-3035
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG use elements.

CVE-2011-3036
Google Chrome before 17.0.963.65 does not properly perform a cast of
an unspecified variable during handling of line boxes, which allows
remote attackers to cause a denial of service or possibly have unknown
other impact via a crafted document.

CVE-2011-3037
Google Chrome before 17.0.963.65 does not properly perform casts of
unspecified variables during the splitting of anonymous blocks, which
allows remote attackers to cause a denial of service or possibly have
unknown other impact via a crafted document.

CVE-2011-3038
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to multi-column handling.

CVE-2011-3039
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to quote handling.

CVE-2011-3040
Google Chrome before 17.0.963.65 does not properly handle text, which
allows remote attackers to cause a denial of service (out-of-bounds
read) via a crafted document.

CVE-2011-3041
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of class
attributes.

CVE-2011-3042
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to the handling of table
sections.

CVE-2011-3043
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving a flexbox (aka flexible
box) in conjunction with the floating of elements.

CVE-2011-3044
Use-after-free vulnerability in Google Chrome before 17.0.963.65
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving SVG animation elements.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.com/search/label/Stable%20updates
http://www.vuxml.org/freebsd/99aef698-66ed-11e1-8288-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71161");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-3031", "CVE-2011-3032", "CVE-2011-3033", "CVE-2011-3034", "CVE-2011-3035", "CVE-2011-3036", "CVE-2011-3037", "CVE-2011-3038", "CVE-2011-3039", "CVE-2011-3040", "CVE-2011-3041", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"17.0.963.65")<0) {
    txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
