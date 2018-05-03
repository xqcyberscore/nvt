# OpenVAS Vulnerability Test
# Description: Oracle Linux Local Check
# $Id: ELSA-2013-1542.nasl 9702 2018-05-03 06:35:02Z cfischer $

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
script_oid("1.3.6.1.4.1.25623.1.0.123523");
script_version("$Revision: 9702 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-05-03 08:35:02 +0200 (Thu, 03 May 2018) $");
script_name("Oracle Linux Local Check: ELSA-2013-1542");
script_tag(name: "insight", value: "ELSA-2013-1542 -  samba security, bug fix, and enhancement update - [3.6.9-164] - resolves: #1008574 - Fix offline logon cache not updating for cross child domain group membership. [3.6.9-163] - resolves: #1015359 - Fix CVE-2013-0213 and CVE-2013-0214 in SWAT. [3.6.9-162] - resolves: #978007 - Fix 'valid users' manpage documentation. [3.6.9-161] - resolves: #997338 - Fix smbstatus as non root user. - resolves: #1003689 - Fix Windows 8 printer driver support. [3.6.9-160] - resolves: #948071 - Group membership is not correct on logins with new AD groups. - resolves: #953985 - User and group info not return from a Trusted Domain. [3.6.9-159] - resolves: #995109 - net ads join - segmentation fault if no realm has been specified. - List all vfs, auth and charset modules in the spec file. [3.6.9-158] - resolves: #984808 - CVE-2013-4124: DoS via integer overflow when reading an EA list [3.6.9-157] - Fix Windows 8 Roaming Profiles. - resolves: #990685 [3.6.9-156] - Fix PIDL parsing with newer versions of gcc. - Fix dereferencing a unique pointer in the WKSSVC server. - resolves: #980382 [3.6.9-155] - Check for system libtevent and require version 0.9.18. - Use tevent epoll backend in winbind. - resolves: #951175 [3.6.9-154] - Add encoding option to 'net printing (migrate or dump)' command. - resolves: #915455 [3.6.9-153] - Fix overwrite of errno in check_parent_exists(). - resolves: #966489 - Fix dir code using dirfd() without vectoring trough VFS calls. - resolves: #971283 [3.6.9-152] - Fix 'map untrusted to domain' with NTLMv2. - resolves: #961932 - Fix the username map optimization. - resolves: #952268 - Fix 'net ads keytab add' not respecting the case. - resolves: #955683 - Fix write operations as guest with security = share - resolves: #953025 - Fix pam_winbind upn to username conversion if you have different separator. - resolves: #949613 - Change chkconfig order to start winbind before netfs. - resolves: #948623 - Fix cache issue when resoliving groups without domain name. - resolves: #927383");
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1542");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1542.html");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind-devel", rpm:"samba-winbind-devel~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }
  if ((res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~3.6.9~164.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

