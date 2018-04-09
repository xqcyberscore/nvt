###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for rtkit CESA-2013:1282 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881798");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-10-03 10:18:34 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2013-4326");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for rtkit CESA-2013:1282 centos6 ");

  tag_insight = "RealtimeKit is a D-Bus system service that changes the scheduling policy of
user processes/threads to SCHED_RR (that is, realtime scheduling mode) on
request. It is intended to be used as a secure mechanism to allow real-time
scheduling to be used by normal user processes.

It was found that RealtimeKit communicated with PolicyKit for authorization
using a D-Bus API that is vulnerable to a race condition. This could have
led to intended PolicyKit authorizations being bypassed. This update
modifies RealtimeKit to communicate with PolicyKit via a different API that
is not vulnerable to the race condition. (CVE-2013-4326)

All rtkit users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.
";

  tag_affected = "rtkit on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1282");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-September/019955.html");
  script_tag(name:"summary", value:"Check for the Version of rtkit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"rtkit", rpm:"rtkit~0.5~2.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
