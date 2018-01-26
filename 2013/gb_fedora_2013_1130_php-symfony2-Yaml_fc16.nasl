###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-symfony2-Yaml FEDORA-2013-1130
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
tag_insight = "The Symfony2 YAML Component parses YAML strings to convert them to PHP arrays.
  It is also able to convert PHP arrays to YAML strings.

  YAML, YAML Ain't Markup Language, is a human friendly data serialization
  standard for all programming languages. YAML is a great format for your
  configuration files. YAML files are as expressive as XML files and as readable
  as INI files.

  The Symfony2 YAML Component implements the YAML 1.2 version of the
  specification.";


tag_affected = "php-symfony2-Yaml on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097596.html");
  script_id(865271);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-01-31 09:25:02 +0530 (Thu, 31 Jan 2013)");
  script_cve_id("CVE-2013-1348", "CVE-2013-1397");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2013-1130");
  script_name("Fedora Update for php-symfony2-Yaml FEDORA-2013-1130");

  script_tag(name: "summary" , value: "Check for the Version of php-symfony2-Yaml");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"php-symfony2-Yaml", rpm:"php-symfony2-Yaml~2.0.22~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
