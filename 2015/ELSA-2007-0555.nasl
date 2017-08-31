# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2007-0555.nasl 6561 2017-07-06 12:03:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122636");
script_version("$Revision: 6561 $");
script_tag(name:"creation_date", value:"2015-10-08 14:49:56 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:03:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2007-0555");
script_tag(name: "insight", value: "ELSA-2007-0555 -  pam security, bug fix, and enhancement update - [0.99.6.2-3.26]- removed realtime default limits (#240123) from the package as it caused regression on machines with nonexistent realtime group[0.99.6.2-3.25]- added and improved translations (#219124)- adjusted the default limits for realtime users (#240123)[0.99.6.2-3.23]- pam_unix: truncated MD5 passwords in shadow shouldn't match (#219258)- pam_limits: add limits.d support (#232700)- pam_limits, pam_time, pam_access: add auditing of failed logins (#232993)- pam_namespace: expand /home/ksharma even when appended with text (#237163) original patch by Ted X. Toth- add some default limits for users in realtime group (#240123)- CVE-2007-3102 - prevent audit log injection through user name (#243204)[0.99.6.2-3.22]- make unix_update helper executable only by root as it isn't useful for regular user anyway[0.99.6.2-3.21]- pam_namespace: better document behavior on failure (#237249)- pam_unix: split out passwd change to a new helper binary (#236316)[0.99.6.2-3.19]- pam_selinux: improve context change auditing (#234781)[0.99.6.2-3.18]- pam_console: always decrement use count (#233581)- pam_namespace: fix parsing config file with unknown users (#234513)[0.99.6.2-3.17]- pam_namespace: unmount poly dir for override users (#229689)- pam_namespace: use raw context for poly dir name (#227345)- pam_namespace: truncate long poly dir name (append hash) (#230120)[0.99.6.2-3.15]- correctly relabel tty in the default case (#229542)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2007-0555");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2007-0555.html");
script_cve_id("CVE-2007-1716","CVE-2007-3102");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"pam", rpm:"pam~0.99.6.2~3.26.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~0.99.6.2~3.26.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

