# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0164.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122602");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:49:02 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0164");
script_tag(name: "insight", value: "ELSA-2008-0164 -  Critical: krb5 security and bugfix update - [1.6.1-17.el5_1.1] - add preliminary patch to fix use of uninitialized pointer / double-free in KDC (CVE-2008-0062,CVE-2008-0063) (#432620, #432621) - add backported patch to fix use-after-free in libgssapi_krb5 (CVE-2007-5901) (#415321) - add backported patch to fix double-free in libgssapi_krb5 (CVE-2007-5971) (#415351) - add preliminary patch to fix incorrect handling of high-numbered descriptors in the RPC library (CVE-2008-0947) (#433596) - fix storage of delegated krb5 credentials when they've been wrapped up in spnego (#436460) - return a delegated credential handle even if the application didn't pass a location to store the flags which would be used to indicate that credentials were delegated (#436465) - add patch to fall back to TCP kpasswd servers for kdc-unreachable, can't-resolve-server, and response-too-big errors (#436467) - use the right sequence numbers when generating password-set/change requests for kpasswd servers after the first one (#436468) - backport from 1.6.3 to initialize a library-allocated get_init_creds_opt structure the same way we would one which was allocated by the calling application, to restore kinit's traditional behavior of doing a password change right when it detects an expired password (#436470)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0164");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0164.html");
script_cve_id("CVE-2007-5901","CVE-2007-5971","CVE-2008-0062","CVE-2008-0063","CVE-2008-0947");
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
  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~17.el5_1.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~17.el5_1.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~17.el5_1.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~17.el5_1.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

