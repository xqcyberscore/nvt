###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for munin FEDORA-2012-13683
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
tag_insight = "Munin is a highly flexible and powerful solution used to create graphs
  of virtually everything imaginable throughout your network, while still
  maintaining a rattling ease of installation and configuration.

  This package contains the grapher/gatherer. You will only need one instance of
  it in your network. It will periodically poll all the nodes in your network
  it's aware of for data, which it in turn will use to create graphs and HTML
  pages, suitable for viewing with your graphical web browser of choice.
  
  Munin is written in Perl, and relies heavily on Tobi Oetiker's excellent
  RRDtool.";

tag_affected = "munin on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-September/088239.html");
  script_id(864726);
  script_version("$Revision: 8245 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 07:29:59 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-09-27 09:04:18 +0530 (Thu, 27 Sep 2012)");
  script_cve_id("CVE-2012-3512");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2012-13683");
  script_name("Fedora Update for munin FEDORA-2012-13683");

  script_tag(name: "summary" , value: "Check for the Version of munin");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"munin", rpm:"munin~2.0.6~2.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
