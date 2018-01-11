###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for sudo CESA-2012:1149 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "The sudo (superuser do) utility allows system administrators to give
  certain users the ability to run commands as root.

  An insecure temporary file use flaw was found in the sudo package's
  post-uninstall script. A local attacker could possibly use this flaw to
  overwrite an arbitrary file via a symbolic link attack, or modify the
  contents of the &quot;/etc/nsswitch.conf&quot; file during the upgrade or removal of
  the sudo package. (CVE-2012-3440)
  
  This update also fixes the following bugs:
  
  * Previously, sudo escaped non-alphanumeric characters in commands using
  &quot;sudo -s&quot; or &quot;sudo -&quot; at the wrong place and interfered with the
  authorization process. Some valid commands were not permitted. Now,
  non-alphanumeric characters escape immediately before the command is
  executed and no longer interfere with the authorization process.
  (BZ#844418)
  
  * Prior to this update, the sudo utility could, under certain
  circumstances, fail to receive the SIGCHLD signal when it was executed
  from a process that blocked the SIGCHLD signal. As a consequence, sudo
  could become suspended and fail to exit. This update modifies the signal
  process mask so that sudo can exit and sends the correct output.
  (BZ#844419)
  
  * The sudo update RHSA-2012:0309 introduced a regression that caused the
  Security-Enhanced Linux (SELinux) context of the &quot;/etc/nsswitch.conf&quot; file
  to change during the installation or upgrade of the sudo package. This
  could cause various services confined by SELinux to no longer be permitted
  to access the file. In reported cases, this issue prevented PostgreSQL and
  Postfix from starting. (BZ#842759)
  
  * Updating the sudo package resulted in the &quot;sudoers&quot; line in
  &quot;/etc/nsswitch.conf&quot; being removed. This update corrects the bug in the
  sudo package's post-uninstall script that caused this issue. (BZ#844420)
  
  * Prior to this update, a race condition bug existed in sudo. When a
  program was executed with sudo, the program could possibly exit
  successfully before sudo started waiting for it. In this situation, the
  program would be left in a zombie state and sudo would wait for it
  endlessly, expecting it to still be running. (BZ#844978)
  
  All users of sudo are advised to upgrade to this updated package, which
  contains backported patches to correct these issues.";

tag_affected = "sudo on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-August/018791.html");
  script_id(881468);
  script_version("$Revision: 8352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 08:01:57 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-08-09 10:21:39 +0530 (Thu, 09 Aug 2012)");
  script_cve_id("CVE-2012-3440");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_xref(name: "CESA", value: "2012:1149");
  script_name("CentOS Update for sudo CESA-2012:1149 centos5 ");

  script_tag(name: "summary" , value: "Check for the Version of sudo");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~14.el5_8.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
