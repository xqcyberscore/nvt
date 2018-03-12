###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_a1650ed14f_php-phpmyadmin-motranslator_fc27.nasl 9076 2018-03-09 14:58:13Z cfischer $
#
# Fedora Update for php-phpmyadmin-motranslator FEDORA-2018-a1650ed14f
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
  script_oid("1.3.6.1.4.1.25623.1.0.874153");
  script_version("$Revision: 9076 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-09 15:58:13 +0100 (Fri, 09 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-27 08:20:03 +0100 (Tue, 27 Feb 2018)");
  script_cve_id("CVE-2018-7260");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php-phpmyadmin-motranslator FEDORA-2018-a1650ed14f");
  script_tag(name: "summary", value: "Check the version of php-phpmyadmin-motranslator");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Translation API for PHP using Gettext MO files.

Features

* All strings are stored in memory for fast lookup
* Fast loading of MO files
* Low level API for reading MO files
* Emulation of Gettext API
* No use of eval() for plural equation

Limitations

* Not suitable for huge MO files which you don&#39 t want to store in memory
* Input and output encoding has to match (preferably UTF-8)

Autoloader: /usr/share/php/PhpMyAdmin/MoTranslator/autoload.php
");
  script_tag(name: "affected", value: "php-phpmyadmin-motranslator on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-a1650ed14f");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/E5UNWHTSG5WZZN3SGQMW6V4I2BQYXLOI");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"php-phpmyadmin-motranslator", rpm:"php-phpmyadmin-motranslator~4.0~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
