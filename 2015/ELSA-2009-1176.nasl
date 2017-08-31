# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1176.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122463");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:45:52 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1176");
script_tag(name: "insight", value: "ELSA-2009-1176 -  python security update - [2.4.3-24.el5_3.6]- Fix all of the low priority security bugs:- Resolves: rhbz#486351- Multiple integer overflows in python core (CVE-2008-2315)- Resolves: 455008- PyString_FromStringAndSize does not check for negative size values (CVE-2008-1887)- Resolves: 443810- Multiple integer overflows discovered by Google (CVE-2008-3143)- Resolves: 455013- Multiple buffer overflows in unicode processing (CVE-2008-3142)- Resolves: 454990- Potential integer underflow and overflow in the PyOS_vsnprintf C API function (CVE-2008-3144)- Resolves: 455018- imageop module multiple integer overflows (CVE-2008-4864)- Resolves: 469656- stringobject, unicodeobject integer overflows (CVE-2008-5031) - Resolves: 470915- integer signedness error in the zlib extension module (CVE-2008-1721)- Resolves: 442005- off-by-one locale.strxfrm() (possible memory disclosure) (CVE-2007-2052)- Resolves: 235093- imageop module heap corruption (CVE-2007-4965)- Resolves: 295971"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1176");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1176.html");
script_cve_id("CVE-2007-2052","CVE-2007-4965","CVE-2008-1721","CVE-2008-1887","CVE-2008-2315","CVE-2008-3142","CVE-2008-3143","CVE-2008-3144","CVE-2008-4864","CVE-2008-5031");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.4.3~24.el5_3.6", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.4.3~24.el5_3.6", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.4.3~24.el5_3.6", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.4.3~24.el5_3.6", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

