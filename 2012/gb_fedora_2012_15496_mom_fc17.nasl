###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mom FEDORA-2012-15496
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
tag_affected = "mom on Fedora 17";
tag_insight = "MOM is a policy-driven tool that can be used to manage overcommitment on KVM
  hosts. Using libvirt, MOM keeps track of active virtual machines on a host. At
  a regular collection interval, data is gathered about the host and guests. Data
  can come from multiple sources (eg. the /proc interface, libvirt API calls, a
  client program connected to a guest, etc). Once collected, the data is
  organized for use by the policy evaluation engine. When started, MOM accepts a
  user-supplied overcommitment policy. This policy is regularly evaluated using
  the latest collected data. In response to certain conditions, the policy may
  trigger reconfiguration of the systems overcommitment mechanisms. Currently
  MOM supports control of memory ballooning and KSM but the architecture is
  designed to accommodate new mechanisms such as cgroups.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-October/090188.html");
  script_id(864796);
  script_version("$Revision: 8295 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 07:29:18 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-10-19 09:47:55 +0530 (Fri, 19 Oct 2012)");
  script_cve_id("CVE-2012-4480");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2012-15496");
  script_name("Fedora Update for mom FEDORA-2012-15496");

  script_tag(name: "summary" , value: "Check for the Version of mom");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"mom", rpm:"mom~0.3.0~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
