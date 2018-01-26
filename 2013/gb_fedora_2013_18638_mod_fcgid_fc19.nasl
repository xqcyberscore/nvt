###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mod_fcgid FEDORA-2013-18638
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
  script_id(867003);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-10-21 10:00:22 +0530 (Mon, 21 Oct 2013)");
  script_cve_id("CVE-2013-4365");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Update for mod_fcgid FEDORA-2013-18638");

  tag_insight = "mod_fcgid is a binary-compatible alternative to the Apache module mod_fastcgi.
mod_fcgid has a new process management strategy, which concentrates on reducing
the number of fastcgi servers, and kicking out corrupt fastcgi servers as soon
as possible.
";

  tag_affected = "mod_fcgid on Fedora 19";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2013-18638");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-October/119288.html");
  script_tag(name: "summary" , value: "Check for the Version of mod_fcgid");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"mod_fcgid", rpm:"mod_fcgid~2.3.9~1.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}