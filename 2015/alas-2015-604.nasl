# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-604.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120594");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-11-08 13:10:56 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2015-604");
script_tag(name: "insight", value: "It was discovered that libwmf did not correctly process certain WMF (Windows Metafiles) with embedded BMP images. By tricking a victim into opening a specially crafted WMF file in an application using libwmf, a remote attacker could possibly use this flaw to execute arbitrary code with the privileges of the user running the application. (CVE-2015-0848 , CVE-2015-4588 )It was discovered that libwmf did not properly process certain WMF files. By tricking a victim into opening a specially crafted WMF file in an application using libwmf, a remote attacker could possibly exploit this flaw to cause a crash or execute arbitrary code with the privileges of the user running the application. (CVE-2015-4696 )It was discovered that libwmf did not properly process certain WMF files. By tricking a victim into opening a specially crafted WMF file in an application using libwmf, a remote attacker could possibly exploit this flaw to cause a crash. (CVE-2015-4695 )The gdPngReadData function in libgd 2.0.34 allows user-assisted attackers to cause a denial of service (CPU consumption) via a crafted PNG image with truncated data, which causes an infinite loop in the png_read_info function in libpng. (CVE-2007-2756 )Buffer overflow in the gdImageStringFTEx function in gdft.c in GD Graphics Library 2.0.33 and earlier allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a crafted string with a JIS encoded font. (CVE-2007-0455 )The _gdGetColors function in gd_gd.c in PHP 5.2.11 and 5.3.x before 5.3.1, and the GD Graphics Library 2.x, does not properly verify a certain colorsTotal structure member, which might allow remote attackers to conduct buffer overflow or buffer over-read attacks via a crafted GD file, a different vulnerability than CVE-2009-3293 . NOTE: some of these details are obtained from third party information. (CVE-2009-3546 )Integer overflow in gdImageCreateTrueColor function in the GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote attackers to have unspecified attack vectors and impact. (CVE-2007-3472 )The gdImageCreateXbm function in the GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote attackers to cause a denial of service (crash) via unspecified vectors involving a gdImageCreate failure. (CVE-2007-3473 )"); 
script_tag(name : "solution", value : "Run yum update libwmf to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-604.html");
script_cve_id("CVE-2007-2756","CVE-2015-4695","CVE-2007-0455","CVE-2009-3546","CVE-2015-4588","CVE-2015-4696","CVE-2007-3472","CVE-2007-3473","CVE-2015-0848","CVE-2009-3293");
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
if ((res = isrpmvuln(pkg:"libwmf-debuginfo", rpm:"libwmf-debuginfo~0.2.8.4~41.11.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libwmf-devel", rpm:"libwmf-devel~0.2.8.4~41.11.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.4~41.11.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"libwmf-lite", rpm:"libwmf-lite~0.2.8.4~41.11.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
