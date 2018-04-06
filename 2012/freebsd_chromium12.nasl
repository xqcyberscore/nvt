#
#VID 1449af37-9eba-11e1-b9c1-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1449af37-9eba-11e1-b9c1-00262d5ed8ee
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

CVE-2011-3083
browser/profiles/profile_impl_io_data.cc in Google Chrome before
19.0.1084.46 does not properly handle a malformed ftp URL in the SRC
attribute of a VIDEO element, which allows remote attackers to cause a
denial of service (NULL pointer dereference and application crash) via
a crafted web page.
CVE-2011-3084
Google Chrome before 19.0.1084.46 does not use a dedicated process for
the loading of links found on an internal page, which might allow
attackers to bypass intended sandbox restrictions via a crafted page.
CVE-2011-3085
The Autofill feature in Google Chrome before 19.0.1084.46 does not
properly restrict field values, which allows remote attackers to cause
a denial of service (UI corruption) and possibly conduct spoofing
attacks via vectors involving long values.
CVE-2011-3086
Use-after-free vulnerability in Google Chrome before 19.0.1084.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving a STYLE element.
CVE-2011-3087
Google Chrome before 19.0.1084.46 does not properly perform window
navigation, which has unspecified impact and remote attack vectors.
CVE-2011-3088
Google Chrome before 19.0.1084.46 does not properly draw hairlines,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2011-3089
Use-after-free vulnerability in Google Chrome before 19.0.1084.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving tables.
CVE-2011-3090
Race condition in Google Chrome before 19.0.1084.46 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to worker processes.
CVE-2011-3091
Use-after-free vulnerability in the IndexedDB implementation in Google
Chrome before 19.0.1084.46 allows remote attackers to cause a denial
of service or possibly have unspecified other impact via unknown
vectors.
CVE-2011-3092
The regex implementation in Google V8, as used in Google Chrome before
19.0.1084.46, allows remote attackers to cause a denial of service
(invalid write operation) or possibly have unspecified other impact
via unknown vectors.
CVE-2011-3093
Google Chrome before 19.0.1084.46 does not properly handle glyphs,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2011-3094
Google Chrome before 19.0.1084.46 does not properly handle Tibetan
text, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2011-3095
The OGG container in Google Chrome before 19.0.1084.46 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via unknown vectors that trigger an out-of-bounds write.
CVE-2011-3096
Use-after-free vulnerability in Google Chrome before 19.0.1084.46 on
Linux allows remote attackers to cause a denial of service or possibly
have unspecified other impact by leveraging an error in the GTK
implementation of the omnibox.
CVE-2011-3097
The PDF functionality in Google Chrome before 19.0.1084.46 allows
remote attackers to cause a denial of service or possibly have
unspecified other impact by leveraging an out-of-bounds write error in
the implementation of sampled functions.
CVE-2011-3099
Use-after-free vulnerability in the PDF functionality in Google Chrome
before 19.0.1084.46 allows remote attackers to cause a denial of
service or possibly have unspecified other impact via vectors
involving a malformed name for the font encoding.
CVE-2011-3100
Google Chrome before 19.0.1084.46 does not properly draw dash paths,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.com/search/label/Stable%20updates
http://www.vuxml.org/freebsd/1449af37-9eba-11e1-b9c1-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71375");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3083", "CVE-2011-3084", "CVE-2011-3085", "CVE-2011-3086", "CVE-2011-3087", "CVE-2011-3088", "CVE-2011-3089", "CVE-2011-3090", "CVE-2011-3091", "CVE-2011-3092", "CVE-2011-3093", "CVE-2011-3094", "CVE-2011-3095", "CVE-2011-3096", "CVE-2011-3097", "CVE-2011-3099", "CVE-2011-3100");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"19.0.1084.46")<0) {
    txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
