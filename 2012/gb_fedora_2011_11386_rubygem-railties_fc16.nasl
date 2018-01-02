###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for rubygem-railties FEDORA-2011-11386
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
tag_affected = "rubygem-railties on Fedora 16";
tag_insight = "Rails internals: application bootup, plugins, generators, and rake tasks.
  Railties is responsible to glue all frameworks together. Overall, it:
  * handles all the bootstrapping process for a Rails application;
  * manager rails command line interface;
  * provides Rails generators core;";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-September/065216.html");
  script_id(863849);
  script_version("$Revision: 8257 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 07:29:46 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-03-19 12:24:59 +0530 (Mon, 19 Mar 2012)");
  script_cve_id("CVE-2011-2931", "CVE-2011-2929", "CVE-2011-2930", "CVE-2011-2932");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2011-11386");
  script_name("Fedora Update for rubygem-railties FEDORA-2011-11386");

  script_tag(name: "summary" , value: "Check for the Version of rubygem-railties");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"rubygem-railties", rpm:"rubygem-railties~3.0.10~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}