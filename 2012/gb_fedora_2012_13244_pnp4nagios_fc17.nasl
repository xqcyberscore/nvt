###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for pnp4nagios FEDORA-2012-13244
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
tag_affected = "pnp4nagios on Fedora 17";
tag_insight = "PNP is an addon to nagios which analyzes performance data provided by plugins
  and stores them automatically into RRD-databases.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-September/086161.html");
  script_id(864704);
  script_version("$Revision: 8352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 08:01:57 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:39:42 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-3457");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2012-13244");
  script_name("Fedora Update for pnp4nagios FEDORA-2012-13244");

  script_tag(name: "summary" , value: "Check for the Version of pnp4nagios");
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

  if ((res = isrpmvuln(pkg:"pnp4nagios", rpm:"pnp4nagios~0.6.16~4.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
