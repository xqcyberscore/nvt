###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for java-1.6.0-openjdk FEDORA-2012-9541
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
tag_affected = "java-1.6.0-openjdk on Fedora 15";
tag_insight = "The OpenJDK runtime environment.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-June/082375.html");
  script_id(864457);
  script_version("$Revision: 8265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 07:29:23 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-06-19 09:36:04 +0530 (Tue, 19 Jun 2012)");
  script_cve_id("CVE-2012-1711", "CVE-2012-1717", "CVE-2012-1716", "CVE-2012-1713",
                "CVE-2012-1719", "CVE-2012-1718", "CVE-2012-1723", "CVE-2012-1724",
                "CVE-2012-1725", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551",
                "CVE-2011-3552", "CVE-2011-3544", "CVE-2011-3521", "CVE-2011-3554",
                "CVE-2011-3389", "CVE-2011-3558", "CVE-2011-3556", "CVE-2011-3557",
                "CVE-2011-3560", "CVE-2011-0872", "CVE-2011-0865", "CVE-2011-0815",
                "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0867", "CVE-2011-0869",
                "CVE-2011-0870", "CVE-2011-0868", "CVE-2011-0871", "CVE-2011-0864");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2012-9541");
  script_name("Fedora Update for java-1.6.0-openjdk FEDORA-2012-9541");

  script_tag(name: "summary" , value: "Check for the Version of java-1.6.0-openjdk");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~65.1.10.8.fc15", rls:"FC15")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
