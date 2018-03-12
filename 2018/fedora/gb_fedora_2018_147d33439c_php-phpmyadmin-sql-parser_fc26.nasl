###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_147d33439c_php-phpmyadmin-sql-parser_fc26.nasl 9076 2018-03-09 14:58:13Z cfischer $
#
# Fedora Update for php-phpmyadmin-sql-parser FEDORA-2018-147d33439c
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874175");
  script_version("$Revision: 9076 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-09 15:58:13 +0100 (Fri, 09 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-02 08:45:49 +0100 (Fri, 02 Mar 2018)");
  script_cve_id("CVE-2018-7260");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php-phpmyadmin-sql-parser FEDORA-2018-147d33439c");
  script_tag(name: "summary", value: "Check the version of php-phpmyadmin-sql-parser");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "A validating SQL lexer and parser with a 
focus on MySQL dialect.
This library was originally developed for phpMyAdmin during
the Google Summer of Code 2015.

Autoloader: /usr/share/php/PhpMyAdmin/SqlParser/autoload.php
");
  script_tag(name: "affected", value: "php-phpmyadmin-sql-parser on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-147d33439c");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YMDHWAKJ2ZMV4H2KEXYT424CDBU2IMEN");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"php-phpmyadmin-sql-parser", rpm:"php-phpmyadmin-sql-parser~4.2.4~3.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
