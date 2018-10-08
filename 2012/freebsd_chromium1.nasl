###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_chromium1.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 68ac6266-25c3-11e1-b63a-00262d5ed8ee
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70593");
  script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_cve_id("CVE-2011-3903", "CVE-2011-3904", "CVE-2011-3905", "CVE-2011-3906", "CVE-2011-3907", "CVE-2011-3908", "CVE-2011-3909", "CVE-2011-3910", "CVE-2011-3911", "CVE-2011-3912", "CVE-2011-3913", "CVE-2011-3914", "CVE-2011-3915", "CVE-2011-3916", "CVE-2011-3917");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11762 $");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3903
Google Chrome before 16.0.912.63 does not properly perform regex
matching, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3904
Use-after-free vulnerability in Google Chrome before 16.0.912.63
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to bidirectional text
(aka bidi) handling.

CVE-2011-3905
libxml2, as used in Google Chrome before 16.0.912.63, allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.

CVE-2011-3906
The PDF parser in Google Chrome before 16.0.912.63 allows remote
attackers to cause a denial of service (out-of-bounds read) via
unspecified vectors.

CVE-2011-3907
The view-source feature in Google Chrome before 16.0.912.63 allows
remote attackers to spoof the URL bar via unspecified vectors.

CVE-2011-3908
Google Chrome before 16.0.912.63 does not properly parse SVG
documents, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3909
The Cascading Style Sheets (CSS) implementation in Google Chrome
before 16.0.912.63 on 64-bit platforms does not properly manage
property arrays, which allows remote attackers to cause a denial of
service (memory corruption) via unspecified vectors.

CVE-2011-3910
Google Chrome before 16.0.912.63 does not properly handle YUV video
frames, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3911
Google Chrome before 16.0.912.63 does not properly handle PDF
documents, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3912
Use-after-free vulnerability in Google Chrome before 16.0.912.63
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to SVG filters.

CVE-2011-3913
Use-after-free vulnerability in Google Chrome before 16.0.912.63
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to Range handling.

CVE-2011-3914
The internationalization (aka i18n) functionality in Google V8, as
used in Google Chrome before 16.0.912.63, allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via unknown vectors that trigger an out-of-bounds write.

CVE-2011-3915
Buffer overflow in Google Chrome before 16.0.912.63 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to PDF fonts.

CVE-2011-3916
Google Chrome before 16.0.912.63 does not properly handle PDF cross
references, which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors.

CVE-2011-3917
Stack-based buffer overflow in FileWatcher in Google Chrome before
16.0.912.63 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via unknown vectors.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/68ac6266-25c3-11e1-b63a-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"chromium");
if(!isnull(bver) && revcomp(a:bver, b:"16.0.912.63")<0) {
  txt += 'Package chromium version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}