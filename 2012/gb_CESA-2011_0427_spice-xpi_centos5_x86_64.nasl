###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for spice-xpi CESA-2011:0427 centos5 x86_64
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
tag_insight = "The Simple Protocol for Independent Computing Environments (SPICE) is a
  remote display protocol used in Red Hat Enterprise Linux for viewing
  virtualized guests running on the Kernel-based Virtual Machine (KVM)
  hypervisor, or on Red Hat Enterprise Virtualization Hypervisor.

  The spice-xpi package provides a plug-in that allows the SPICE client to
  run from within Mozilla Firefox.
  
  An uninitialized pointer use flaw was found in the SPICE Firefox plug-in.
  If a user were tricked into visiting a malicious web page with Firefox
  while the SPICE plug-in was enabled, it could cause Firefox to crash or,
  possibly, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-1179)
  
  Users of spice-xpi should upgrade to this updated package, which contains a
  backported patch to correct this issue. After installing the update,
  Firefox must be restarted for the changes to take effect.";

tag_affected = "spice-xpi on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-April/017304.html");
  script_id(881241);
  script_version("$Revision: 8249 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 07:29:56 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:08:08 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1179");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2011:0427");
  script_name("CentOS Update for spice-xpi CESA-2011:0427 centos5 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of spice-xpi");
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

  if ((res = isrpmvuln(pkg:"spice-xpi", rpm:"spice-xpi~2.2~2.3.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
