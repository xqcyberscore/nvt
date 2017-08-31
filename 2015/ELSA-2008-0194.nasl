# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0194.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122592");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:48:46 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0194");
script_tag(name: "insight", value: "ELSA-2008-0194 -  xen security and bug fix update - [3.0.3-41.el5_1.5]- Disable QEMU image format auto-detection CVE-2008-2004 (rhbz #444700)[3.0.3-41.el5_1.4]- Fix PVFB to validate frame buffer description (rhbz #443376)- Fix PVFB to cope with bogus update requests (rhbz #368931)[3.0.3-41.el5_1.3]- Fix QEMU buffer overflow CVE-2007-5730 (rhbz #360381)- Fix QEMU block device extents checking CVE-2008-0928 (rhbz #433560)[3.0.3-41.el5_1.2]- Fix FV O_DIRECT flushing (rhbz #435495)[3.0.3-41.el5_1.1]- Fixed xenbaked tmpfile flaw (CVE-2007-3919) (rhbz #350421)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0194");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0194.html");
script_cve_id("CVE-2007-3919","CVE-2007-5730","CVE-2008-0928","CVE-2008-1943","CVE-2008-1944","CVE-2008-2004");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~41.el5_1.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~41.el5_1.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~41.el5_1.5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

