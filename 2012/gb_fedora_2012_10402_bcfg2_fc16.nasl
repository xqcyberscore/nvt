###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for bcfg2 FEDORA-2012-10402
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
tag_insight = "Bcfg2 helps system administrators produce a consistent, reproducible,
  and verifiable description of their environment, and offers
  visualization and reporting tools to aid in day-to-day administrative
  tasks. It is the fifth generation of configuration management tools
  developed in the Mathematics and Computer Science Division of Argonne
  National Laboratory.

  It is based on an operational model in which the specification can be
  used to validate and optionally change the state of clients, but in a
  feature unique to Bcfg2 the client's response to the specification can
  also be used to assess the completeness of the specification. Using
  this feature, bcfg2 provides an objective measure of how good a job an
  administrator has done in specifying the configuration of client
  systems. Bcfg2 is therefore built to help administrators construct an
  accurate, comprehensive specification.";

tag_affected = "bcfg2 on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-October/090847.html");
  script_id(864818);
  script_version("$Revision: 8265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 07:29:23 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-10-29 11:02:08 +0530 (Mon, 29 Oct 2012)");
  script_cve_id("CVE-2012-3366");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2012-10402");
  script_name("Fedora Update for bcfg2 FEDORA-2012-10402");

  script_tag(name: "summary" , value: "Check for the Version of bcfg2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"bcfg2", rpm:"bcfg2~1.2.3~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
