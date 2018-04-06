###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for groff FEDORA-2012-8590
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
tag_insight = "Groff is a document formatting system. Groff takes standard text and
  formatting commands as input and produces formatted output. The
  created documents can be shown on a display or printed on a printer.
  Groff's formatting commands allow you to specify font type and size,
  bold type, italic type, the number and size of columns on a page, and
  more.

  Groff can also be used to format man pages. If you are going to use
  groff with the X Window System, you will also need to install the
  groff-x11 package.";

tag_affected = "groff on Fedora 15";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-June/081960.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864284");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-08 10:10:57 +0530 (Fri, 08 Jun 2012)");
  script_cve_id("CVE-2009-5044", "CVE-2009-5080", "CVE-2009-5081");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_xref(name: "FEDORA", value: "2012-8590");
  script_name("Fedora Update for groff FEDORA-2012-8590");

  script_tag(name: "summary" , value: "Check for the Version of groff");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"groff", rpm:"groff~1.21~4.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
