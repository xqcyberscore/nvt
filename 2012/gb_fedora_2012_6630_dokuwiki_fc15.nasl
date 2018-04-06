###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for dokuwiki FEDORA-2012-6630
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
tag_insight = "DokuWiki is a standards compliant, simple to use Wiki, mainly aimed at creating
  documentation of any kind. It has a simple but powerful syntax which makes sure
  the datafiles remain readable outside the Wiki and eases the creation of
  structured texts.

  All data is stored in plain text files no database is required.";

tag_affected = "dokuwiki on Fedora 15";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-June/082120.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864449");
  script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-15 09:44:25 +0530 (Fri, 15 Jun 2012)");
  script_cve_id("CVE-2012-2129", "CVE-2012-2128");
  script_xref(name: "FEDORA", value: "2012-6630");
  script_name("Fedora Update for dokuwiki FEDORA-2012-6630");

  script_tag(name: "summary" , value: "Check for the Version of dokuwiki");
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

  if ((res = isrpmvuln(pkg:"dokuwiki", rpm:"dokuwiki-0~0.10.20110525.a.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
