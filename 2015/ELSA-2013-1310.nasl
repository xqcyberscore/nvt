# OpenVAS Vulnerability Test
# Description: Oracle Linux Local Check
# $Id: ELSA-2013-1310.nasl 9702 2018-05-03 06:35:02Z cfischer $

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
script_oid("1.3.6.1.4.1.25623.1.0.123558");
script_version("$Revision: 9702 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:30 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-05-03 08:35:02 +0200 (Thu, 03 May 2018) $");
script_name("Oracle Linux Local Check: ELSA-2013-1310");
script_tag(name: "insight", value: "ELSA-2013-1310 -  samba3x security and bug fix update - [3.6.6-0.136] - resolves: #984807 - CVE-2013-4124: DoS via integer overflow when reading an EA list [3.6.6-0.135] - Fix PIDL parsing with newer versions of gcc. - Fix dereferencing a unique pointer in the WKSSVC server. - resolves: #982484 [3.6.6-0.134] - Check for system libtevent and require version 0.9.18. - Use tevent epoll backend in winbind. - resolves: #869295 [3.6.6-0.133] - Fix smbstatus code dump when a file entry has delete tokens. - resolves: #962840 [3.6.6-0.132] - Fix possible segfaults with group caching patch. - related: #948923 [3.6.6-0.131] - Fix CVE-2013-0213 and CVE-2013-0214. - resolves: #957591 [3.6.6-0.130] - Fix netlogon failover for LogonSamLogon. - resolves: #862872 - Fix write operations as guest with security = share - resolves: #905071 - Disable building cifs idmap and acl binaries. - resolves: #873692 - Change chkconfig order to start winbind before netfs. - resolves: #948614 - Fix cache issue when resoliving groups without domain name. - resolves: #948923 - Fix pam_winbind upn to username conversion if you have different separator. - resolves: #949611 - Fix the username map optimization. - resolves: #917564 - Fix leaking sockets of smb dc connection. - resolves: #883861 - Fix 'net ads keytab add' not respecting the case. - resolves: #955680 - Fix 'map untrusted to domain' with NTLMv2. - resolves: #947999");
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1310");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1310.html");
script_cve_id("CVE-2013-0213","CVE-2013-0214","CVE-2013-4124");
script_tag(name:"cvss_base", value:"5.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"samba3x", rpm:"samba3x~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-client", rpm:"samba3x-client~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-common", rpm:"samba3x-common~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-doc", rpm:"samba3x-doc~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-domainjoin-gui", rpm:"samba3x-domainjoin-gui~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-swat", rpm:"samba3x-swat~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-winbind", rpm:"samba3x-winbind~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba3x-winbind-devel", rpm:"samba3x-winbind-devel~3.6.6~0.136.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

