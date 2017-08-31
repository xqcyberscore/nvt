# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-365.nasl 6769 2017-07-20 09:56:33Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.120140");
script_version("$Revision: 6769 $");
script_tag(name:"creation_date", value:"2015-09-08 13:18:27 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-365");
script_tag(name: "insight", value: "Use-after-free vulnerability in the t2p_readwrite_pdf_image function in tools/tiff2pdf.c in libtiff 4.0.3 allows remote attackers to cause a denial of service (crash) or possible execute arbitrary code via a crafted TIFF image. The LZW decompressor in the gif2tiff tool in libtiff 4.0.3 and earlier allows context-dependent attackers to cause a denial of service (out-of-bounds write and crash) or possibly execute arbitrary code via a crafted GIF image. Heap-based buffer overflow in the readgifimage function in the gif2tiff tool in libtiff 4.0.3 and earlier allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a crafted height and width values in a GIF image. Multiple buffer overflows in libtiff before 4.0.3 allow remote attackers to cause a denial of service (out-of-bounds write) via a crafted (1) extension block in a GIF image or (2) GIF raster image to tools/gif2tiff.c or (3) a long filename for a TIFF image to tools/rgb2ycbcr.c. NOTE: vectors 1 and 3 are disputed by Red Hat, which states that the input cannot exceed the allocated buffer size."); 
script_tag(name : "solution", value : "Run yum update libtiff to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-365.html");
script_cve_id("CVE-2013-4232", "CVE-2013-4244", "CVE-2013-4243", "CVE-2013-4231");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.3~15.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.3~15.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libtiff-static", rpm:"libtiff-static~4.0.3~15.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libtiff-debuginfo", rpm:"libtiff-debuginfo~4.0.3~15.19.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
