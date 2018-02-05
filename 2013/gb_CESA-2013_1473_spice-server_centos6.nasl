###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for spice-server CESA-2013:1473 centos6 
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
  script_id(881825);
  script_version("$Revision: 8650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:59 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-11-08 10:52:46 +0530 (Fri, 08 Nov 2013)");
  script_cve_id("CVE-2013-4282");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("CentOS Update for spice-server CESA-2013:1473 centos6 ");

  tag_insight = "The Simple Protocol for Independent Computing Environments (SPICE) is a
remote display protocol for virtual environments. SPICE users can access a
virtualized desktop or server from the local system or any system with
network access to the server. SPICE is used in Red Hat Enterprise Linux for
viewing virtualized guests running on the Kernel-based Virtual Machine
(KVM) hypervisor or on Red Hat Enterprise Virtualization Hypervisors.

A stack-based buffer overflow flaw was found in the way the
reds_handle_ticket() function in the spice-server library handled
decryption of ticket data provided by the client. A remote user able to
initiate a SPICE connection to an application acting as a SPICE server
could use this flaw to crash the application. (CVE-2013-4282)

This issue was discovered by Tomas Jamrisko of Red Hat.

All spice-server users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue.
";

  tag_affected = "spice-server on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1473");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-October/019996.html");
  script_tag(name: "summary" , value: "Check for the Version of spice-server");
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

  if ((res = isrpmvuln(pkg:"spice-server", rpm:"spice-server~0.12.0~12.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-server-devel", rpm:"spice-server-devel~0.12.0~12.el6_4.5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}