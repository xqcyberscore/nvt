# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0696.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.123157");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:04 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0696");
script_tag(name: "insight", value: "ELSA-2015-0696 -  freetype security update - [2.3.11-15.el6_6.1]- Fixes CVE-2014-9657 - Check minimum size of record_size.- Fixes CVE-2014-9658 - Use correct value for minimum table length test.- Fixes CVE-2014-9675 - New macro that checks one character more than strncmp.- Fixes CVE-2014-9660 - Check _BDF_GLYPH_BITS.- Fixes CVE-2014-9661 - Initialize face->ttf_size. - Always set face->ttf_size directly. - Exclusively use the truetype font driver for loading the font contained in the sfnts array.- Fixes CVE-2014-9663 - Fix order of validity tests.- Fixes CVE-2014-9664 - Add another boundary testing. - Fix boundary testing.- Fixes CVE-2014-9667 - Protect against addition overflow.- Fixes CVE-2014-9669 - Protect against overflow in additions and multiplications.- Fixes CVE-2014-9670 - Add sanity checks for row and column values.- Fixes CVE-2014-9671 - Check size and offset values.- Fixes CVE-2014-9673 - Fix integer overflow by a broken POST table in resource-fork.- Fixes CVE-2014-9674 - Fix integer overflow by a broken POST table in resource-fork. - Additional overflow check in the summation of POST fragment lengths.- Work around behaviour of X11s pcfWriteFont and pcfReadFont functions- Resolves: #1197737[2.3.11-15]- Fix CVE-2012-5669 (Use correct array size for checking glyph_enc)- Resolves: #903543"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0696");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0696.html");
script_cve_id("CVE-2014-9657","CVE-2014-9658","CVE-2014-9660","CVE-2014-9661","CVE-2014-9663","CVE-2014-9664","CVE-2014-9667","CVE-2014-9669","CVE-2014-9670","CVE-2014-9671","CVE-2014-9673","CVE-2014-9674","CVE-2014-9675");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.4.11~10.el7_1.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.4.11~10.el7_1.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.4.11~10.el7_1.1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.3.11~15.el6_6.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.3.11~15.el6_6.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.3.11~15.el6_6.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

