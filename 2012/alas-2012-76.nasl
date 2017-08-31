# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-76.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120148");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:18:36 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-76");
script_tag(name: "insight", value: "A flaw was found in the way ImageMagick processed images with malformed Exchangeable image file format (Exif) metadata. An attacker could create a specially-crafted image file that, when opened by a victim, would cause ImageMagick to crash or, potentially, execute arbitrary code. (CVE-2012-0247 )A denial of service flaw was found in the way ImageMagick processed images with malformed Exif metadata. An attacker could create a specially-crafted image file that, when opened by a victim, could cause ImageMagick to enter an infinite loop. (CVE-2012-0248 )It was found that ImageMagick utilities tried to load ImageMagick configuration files from the current working directory. If a user ran an ImageMagick utility in an attacker-controlled directory containing a specially-crafted ImageMagick configuration file, it could cause the utility to execute arbitrary code. (CVE-2010-4167 )An integer overflow flaw was found in the way ImageMagick processed certain Exif tags with a large components count. An attacker could create a specially-crafted image file that, when opened by a victim, could cause ImageMagick to access invalid memory and crash. (CVE-2012-0259 )A denial of service flaw was found in the way ImageMagick decoded certain JPEG images. A remote attacker could provide a JPEG image with specially-crafted sequences of RST0 up to RST7 restart markers (used to indicate the input stream to be corrupted), which once processed by ImageMagick, would cause it to consume excessive amounts of memory and CPU time. (CVE-2012-0260 )An out-of-bounds buffer read flaw was found in the way ImageMagick processed certain TIFF image files. A remote attacker could provide a TIFF image with a specially-crafted Exif IFD value (the set of tags for recording Exif-specific attribute information), which once opened by ImageMagick, would cause it to crash. (CVE-2012-1798 )"); 
script_tag(name : "solution", value : "Run yum update ImageMagick to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-76.html");
script_cve_id("CVE-2012-0259", "CVE-2012-0247", "CVE-2012-0248", "CVE-2010-4167", "CVE-2012-1798", "CVE-2012-0260");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ImageMagick-debuginfo", rpm:"ImageMagick-debuginfo~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ImageMagick-c++-devel", rpm:"ImageMagick-c++-devel~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.5.4.7~6.12.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
