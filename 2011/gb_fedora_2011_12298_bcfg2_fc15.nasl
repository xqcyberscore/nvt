###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for bcfg2 FEDORA-2011-12298
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
tag_insight = "Bcfg2 helps system administrators produce a consistent, reproducible,
  and verifiable description of their environment, and offers
  visualization and reporting tools to aid in day-to-day administrative
  tasks. It is the fifth generation of configuration management tools
  developed in the Mathematics and Computer Science Division of Argonne
  National Laboratory.

  It is based on an operational model in which the specification can be
  used to validate and optionally change the state of clients, but in a
  feature unique to bcfg2 the client's response to the specification can
  also be used to assess the completeness of the specification. Using
  this feature, bcfg2 provides an objective measure of how good a job an
  administrator has done in specifying the configuration of client
  systems. Bcfg2 is therefore built to help administrators construct an
  accurate, comprehensive specification.
  
  Bcfg2 has been designed from the ground up to support gentle
  reconciliation between the specification and current client states. It
  is designed to gracefully cope with manual system modifications.
  
  Finally, due to the rapid pace of updates on modern networks, client
  systems are constantly changing; if required in your environment,
  Bcfg2 can enable the construction of complex change management and
  deployment strategies.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "bcfg2 on Fedora 15";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-September/066071.html");
  script_oid("1.3.6.1.4.1.25623.1.0.863529");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-20 15:38:54 +0200 (Tue, 20 Sep 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2011-12298");
  script_cve_id("CVE-2011-3211");
  script_name("Fedora Update for bcfg2 FEDORA-2011-12298");

  script_tag(name:"summary", value:"Check for the Version of bcfg2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"bcfg2", rpm:"bcfg2~1.1.2~2.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
