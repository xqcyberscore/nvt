#
#VID fe1976c2-5317-11e1-9e99-00262d5ed8ee
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID fe1976c2-5317-11e1-9e99-00262d5ed8ee
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

CVE-2011-3953
Google Chrome before 17.0.963.46 does not prevent monitoring of the
clipboard after a paste event, which has unspecified impact and remote
attack vectors.

CVE-2011-3954
Google Chrome before 17.0.963.46 allows remote attackers to cause a
denial of service (application crash) via vectors that trigger a large
amount of database usage.

CVE-2011-3955
Google Chrome before 17.0.963.46 allows remote attackers to cause a
denial of service (application crash) or possibly have unspecified
other impact via vectors that trigger the aborting of an IndexedDB
transaction.

CVE-2011-3956
The extension implementation in Google Chrome before 17.0.963.46 does
not properly handle sandboxed origins, which might allow remote
attackers to bypass the Same Origin Policy via a crafted extension.

CVE-2011-3957
Use-after-free vulnerability in the garbage-collection functionality
in Google Chrome before 17.0.963.46 allows remote attackers to cause a
denial of service or possibly have unspecified other impact via
vectors involving PDF documents.

CVE-2011-3958
Google Chrome before 17.0.963.46 does not properly perform casts of
variables during handling of a column span, which allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via a crafted document.

CVE-2011-3959
Buffer overflow in the locale implementation in Google Chrome before
17.0.963.46 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.

CVE-2011-3960
Google Chrome before 17.0.963.46 does not properly decode audio data,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3961
Race condition in Google Chrome before 17.0.963.46 allows remote
attackers to execute arbitrary code via vectors that trigger a crash
of a utility process.

CVE-2011-3962
Google Chrome before 17.0.963.46 does not properly perform path
clipping, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3963
Google Chrome before 17.0.963.46 does not properly handle PDF FAX
images, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3964
Google Chrome before 17.0.963.46 does not properly implement the
drag-and-drop feature, which makes it easier for remote attackers to
spoof the URL bar via unspecified vectors.

CVE-2011-3965
Google Chrome before 17.0.963.46 does not properly check signatures,
which allows remote attackers to cause a denial of service
(application crash) via unspecified vectors.

CVE-2011-3966
Use-after-free vulnerability in Google Chrome before 17.0.963.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to error handling for
Cascading Style Sheets (CSS) token-sequence data.

CVE-2011-3967
Unspecified vulnerability in Google Chrome before 17.0.963.46 allows
remote attackers to cause a denial of service (application crash) via
a crafted certificate.

CVE-2011-3968
Use-after-free vulnerability in Google Chrome before 17.0.963.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors involving Cascading Style Sheets
(CSS) token sequences.

CVE-2011-3969
Use-after-free vulnerability in Google Chrome before 17.0.963.46
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to layout of SVG
documents.

CVE-2011-3970
libxslt, as used in Google Chrome before 17.0.963.46, allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.

CVE-2011-3971
Use-after-free vulnerability in Google Chrome before 17.0.963.46
allows user-assisted remote attackers to cause a denial of service or
possibly have unspecified other impact via vectors related to
mousemove events.

CVE-2011-3972
The shader translator implementation in Google Chrome before
17.0.963.46 allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://googlechromereleases.blogspot.com/search/label/Stable%20updates
http://www.vuxml.org/freebsd/fe1976c2-5317-11e1-9e99-00262d5ed8ee.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70732");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3953", "CVE-2011-3954", "CVE-2011-3955", "CVE-2011-3956", "CVE-2011-3957", "CVE-2011-3958", "CVE-2011-3959", "CVE-2011-3960", "CVE-2011-3961", "CVE-2011-3962", "CVE-2011-3963", "CVE-2011-3964", "CVE-2011-3965", "CVE-2011-3966", "CVE-2011-3967", "CVE-2011-3968", "CVE-2011-3969", "CVE-2011-3970", "CVE-2011-3971", "CVE-2011-3972");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)");
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

txt = "";
vuln = 0;
txt = "";
bver = portver(pkg:"chromium");
if(!isnull(bver) && revcomp(a:bver, b:"17.0.963.46")<0) {
    txt += 'Package chromium version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
