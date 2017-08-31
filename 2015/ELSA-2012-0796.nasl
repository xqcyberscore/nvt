# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0796.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123881");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:09:48 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0796");
script_tag(name: "insight", value: "ELSA-2012-0796 -  rsyslog security, bug fix, and enhancement update - [5.8.10-2]- add patch to update information on debugging in the man page Resolves: #820311- add patch to prevent debug output to stdout after forking Resolves: #820996- add patch to support ssl certificates with domain names longer than 128 chars Resolves: #822118[5.8.10-1]- rebase to rsyslog 5.8.10 Resolves: #803550 Resolves: #805424 Resolves: #813079 Resolves: #813084- consider lock file in 'status' action Resolves: #807608- add impstats and imptcp modules- include new license text files- specify which versions of sysklogd are obsoleted[5.8.7-1]- rebase to rsyslog-5.8.7 - change license from 'GPLv3+' to '(GPLv3+ and ASL 2.0)' http://blog.gerhards.net/2012/01/rsyslog-licensing-update.html - remove patches obsoleted by rebase - add patches for better sysklogd compatibility (taken from upstream) - update included files for the new major version Resolves: #672182 Resolves: #727380 Resolves: #756664 Resolves: #767527 Resolves: #769025- add several directories for storing auxiliary data Resolves: #740420- fix source package URL"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0796");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0796.html");
script_cve_id("CVE-2011-4623");
script_tag(name:"cvss_base", value:"2.1");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rsyslog-gnutls", rpm:"rsyslog-gnutls~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rsyslog-gssapi", rpm:"rsyslog-gssapi~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rsyslog-mysql", rpm:"rsyslog-mysql~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rsyslog-pgsql", rpm:"rsyslog-pgsql~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rsyslog-relp", rpm:"rsyslog-relp~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"rsyslog-snmp", rpm:"rsyslog-snmp~5.8.10~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

