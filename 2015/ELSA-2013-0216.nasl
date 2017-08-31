# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0216.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123737");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:53 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0216");
script_tag(name: "insight", value: "ELSA-2013-0216 -  freetype security update - [2.3.11-14.el6_3.1]- Fix CVE-2012-5669 (Use correct array size for checking 'glyph_enc')- Resolves: #903542[2.3.11-14]- A little change in configure part- Related: #723468[2.3.11-13]- Fix CVE-2012-{1126, 1127, 1130, 1131, 1132, 1134, 1136, 1137, 1139, 1140, 1141, 1142, 1143, 1144}- Properly initialize array 'result' in FT_Outline_Get_Orientation()- Check bytes per row for overflow in _bdf_parse_glyphs()- Resolves: #806269[2.3.11-12]- Add freetype-2.3.11-CVE-2011-3439.patch (Various loading fixes.)- Resolves: #754012[2.3.11-11]- Add freetype-2.3.11-CVE-2011-3256.patch (Handle some border cases.)- Resolves: #747084[2.3.11-10]- Use -fno-strict-aliasing instead of __attribute__((__may_alias__))- Resolves: #723468[2.3.11-9]- Allow FT_Glyph to alias (to pass Rpmdiff)- Resolves: #723468[2.3.11-8]- Add freetype-2.3.11-CVE-2011-0226.patch (Add better argument check for 'callothersubr'.) - based on patches by Werner Lemberg, Alexei Podtelezhnikov and Matthias Drochner- Resolves: #723468[2.3.11-7]- Add freetype-2.3.11-CVE-2010-3855.patch (Protect against invalid 'runcnt' values.)- Resolves: #651762"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0216");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0216.html");
script_cve_id("CVE-2012-5669");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.2.1~32.el5_9.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.2.1~32.el5_9.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.2.1~32.el5_9.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.3.11~14.el6_3.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-demos", rpm:"freetype-demos~2.3.11~14.el6_3.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.3.11~14.el6_3.1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

