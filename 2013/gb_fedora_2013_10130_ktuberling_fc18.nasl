###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ktuberling FEDORA-2013-10130
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

tag_affected = "ktuberling on Fedora 18";
tag_insight = "KTuberling a simple constructor game suitable for children and adults
  alike. The idea of the game is based around a once popular doll making
  concept. A potato was decorated with various small artifacts to make it
  look more like a tiny person. KTuberling however, goes much further in
  terms of content and adds a surprising variety of different themes.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(865768);
  script_version("$Revision: 8494 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 07:57:55 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-06-13 10:02:38 +0530 (Thu, 13 Jun 2013)");
  script_cve_id("CVE-2013-2120");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for ktuberling FEDORA-2013-10130");

  script_xref(name: "FEDORA", value: "2013-10130");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/108615.html");
  script_tag(name: "summary" , value: "Check for the Version of ktuberling");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"ktuberling", rpm:"ktuberling~4.10.4~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
