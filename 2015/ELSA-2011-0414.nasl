# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0414.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122201");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:43 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0414");
script_tag(name: "insight", value: "ELSA-2011-0414 -  policycoreutils security update - policycoreutils:[2.0.83-19.8]- Fix seunshare to work with /tmp content when SELinux context is not providedResolves: #679689[2.0.83-19.7]- put back correct chcon- Latest fixes for seunshare[2.0.83-19.6]- Fix rsync command to work if the directory is old.- Fix all testsResolves: #679689[2.0.83-19.5]- Add requires rsync and fix man page for seunshare[2.0.83-19.4]- fix to sandbox - Fix seunshare to use more secure handling of /tmp - Rewrite seunshare to make sure /tmp is mounted stickybit owned by root - Change to allow sandbox to run on nfs homedirs, add start python script - change default location of HOMEDIR in sandbox to /tmp/.sandbox_home_* - Move seunshare to sandbox package - Fix sandbox to show correct types in usage statementselinux-policy:[3.7.19-54.0.1.el6_0.5]- Allow ocfs2 to be mounted with file_t type.[3.7.19-54.el6_0.5]- seunshare needs to be able to mounton nfs/cifs/fusefs homedirsResolves: #684918[3.7.19-54.el6_0.4]- Fix to sandbox * selinux-policy fixes for policycoreutils sandbox changes - Fix seunshare to use more secure handling of /tmp - Change to allow sandbox to run on nfs homedirs, add start python script"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0414");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0414.html");
script_cve_id("CVE-2011-1011");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"policycoreutils", rpm:"policycoreutils~2.0.83~19.8.el6_0", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"policycoreutils-gui", rpm:"policycoreutils-gui~2.0.83~19.8.el6_0", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"policycoreutils-newrole", rpm:"policycoreutils-newrole~2.0.83~19.8.el6_0", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"policycoreutils-python", rpm:"policycoreutils-python~2.0.83~19.8.el6_0", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"policycoreutils-sandbox", rpm:"policycoreutils-sandbox~2.0.83~19.8.el6_0", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"selinux-policy-doc", rpm:"selinux-policy-doc~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"selinux-policy-minimum", rpm:"selinux-policy-minimum~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"selinux-policy-mls", rpm:"selinux-policy-mls~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"selinux-policy-targeted", rpm:"selinux-policy-targeted~3.7.19~54.0.1.el6_0.5", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

