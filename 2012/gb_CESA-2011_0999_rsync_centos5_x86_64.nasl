###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rsync CESA-2011:0999 centos5 x86_64
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
tag_insight = "rsync is a program for synchronizing files over a network.

  A flaw was found in the way the rsync daemon handled the &quot;filter&quot;,
  &quot;exclude&quot;, and &quot;exclude from&quot; options, used for hiding files and preventing
  access to them from rsync clients. A remote attacker could use this flaw to
  bypass those restrictions by using certain command line options and
  symbolic links, allowing the attacker to overwrite those files if they knew
  their file names and had write access to them. (CVE-2007-6200)
  
  Note: This issue only affected users running rsync as a writable daemon:
  &quot;read only&quot; set to &quot;false&quot; in the rsync configuration file (for example,
  &quot;/etc/rsyncd.conf&quot;). By default, this option is set to &quot;true&quot;.
  
  This update also fixes the following bugs:
  
  * The rsync package has been upgraded to upstream version 3.0.6, which
  provides a number of bug fixes and enhancements over the previous version.
  (BZ#339971)
  
  * When running an rsync daemon that was receiving files, a deferred info,
  error or log message could have been sent directly to the sender instead of
  being handled by the &quot;rwrite()&quot; function in the generator. Also, under
  certain circumstances, a deferred info or error message from the receiver
  could have bypassed the log file and could have been sent only to the
  client process. As a result, an &quot;unexpected tag 3&quot; fatal error could have
  been displayed. These problems have been fixed in this update so that an
  rsync daemon receiving files now works as expected. (BZ#471182)
  
  * Prior to this update, the rsync daemon called a number of timezone-using
  functions after doing a chroot. As a result, certain C libraries were
  unable to generate proper timestamps from inside a chrooted daemon. This
  bug has been fixed in this update so that the rsync daemon now calls the
  respective timezone-using functions prior to doing a chroot, and proper
  timestamps are now generated as expected. (BZ#575022)
  
  * When running rsync under a non-root user with the &quot;-A&quot; (&quot;--acls&quot;) option
  and without using the &quot;--numeric-ids&quot; option, if there was an Access
  Control List (ACL) that included a group entry for a group that the
  respective user was not a member of on the receiving side, the
  &quot;acl_set_file()&quot; function returned an invalid argument value (&quot;EINVAL&quot;).
  This was caused by rsync mistakenly mapping the group name to the Group ID
  &quot;GID_NONE&quot; (&quot;-1&quot;), which failed. The bug has been fixed in this update so
  that no ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "rsync on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-September/017960.html");
  script_id(881391);
  script_version("$Revision: 8273 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 07:29:19 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:40:20 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2007-6200");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2011:0999");
  script_name("CentOS Update for rsync CESA-2011:0999 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of rsync");
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

  if ((res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.0.6~4.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
