###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for bash RHSA-2011:0261-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Bash (Bourne-again shell) is the default shell for Red Hat Enterprise
  Linux.

  It was found that certain scripts bundled with the Bash documentation
  created temporary files in an insecure way. A malicious, local user could
  use this flaw to conduct a symbolic link attack, allowing them to overwrite
  the contents of arbitrary files accessible to the victim running the
  scripts. (CVE-2008-5374)
  
  This update also fixes the following bugs:
  
  * If a child process's PID was the same as the PID of a previously ended
  child process, Bash did not wait for that child process. In some cases this
  caused &quot;Resource temporarily unavailable&quot; errors. With this update, Bash
  recycles PIDs and waits for processes with recycled PIDs. (BZ#521134)
  
  * Bash's built-in &quot;read&quot; command had a memory leak when &quot;read&quot; failed due
  to no input (pipe for stdin). With this update, the memory is correctly
  freed. (BZ#537029)
  
  * Bash did not correctly check for a valid multi-byte string when setting
  the IFS value, causing Bash to crash. With this update, Bash checks the
  multi-byte string and no longer crashes. (BZ#539536)
  
  * Bash incorrectly set locale settings when using the built-in &quot;export&quot;
  command and setting the locale on the same line (for example, with
  &quot;LC_ALL=C export LC_ALL&quot;). With this update, Bash correctly sets locale
  settings. (BZ#539538)
  
  All bash users should upgrade to these updated packages, which contain
  backported patches to correct these issues.";

tag_affected = "bash on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-February/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870392");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-18 15:15:05 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2011:0261-01");
  script_cve_id("CVE-2008-5374");
  script_name("RedHat Update for bash RHSA-2011:0261-01");

  script_tag(name:"summary", value:"Check for the Version of bash");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~3.0~27.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bash-debuginfo", rpm:"bash-debuginfo~3.0~27.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
