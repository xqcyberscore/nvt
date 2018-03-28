###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_a89ccf7133_php_fc27.nasl 9226 2018-03-28 03:48:50Z ckuersteiner $
#
# Fedora Update for php FEDORA-2018-a89ccf7133
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
  script_oid("1.3.6.1.4.1.25623.1.0.874229");
  script_version("$Revision: 9226 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-28 05:48:50 +0200 (Wed, 28 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-14 08:42:39 +0100 (Wed, 14 Mar 2018)");
  script_cve_id("CVE-2018-7584");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php FEDORA-2018-a89ccf7133");
  script_tag(name: "summary", value: "Check the version of php");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "PHP is an HTML-embedded scripting 
language. PHP attempts to make it easy for developers to write dynamically 
generated web pages. PHP also offers built-in database integration for several 
commercial and non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common use of PHP 
coding is probably as a replacement for CGI scripts.

The php package contains the module (often referred to as mod_php)
which adds support for the PHP language to Apache HTTP Server.
");
  script_tag(name: "affected", value: "php on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-a89ccf7133");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N4EQWOYJBG2RJRUHO4FBYTOQPICKHPMX");
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

  if ((res = isrpmvuln(pkg:"php", rpm:"php~7.1.15~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
