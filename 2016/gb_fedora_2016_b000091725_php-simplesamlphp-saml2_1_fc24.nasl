###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-simplesamlphp-saml2_1 FEDORA-2016-b000091725
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.872135");
  script_version("$Revision: 6631 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:36:10 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2016-12-14 06:18:14 +0100 (Wed, 14 Dec 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php-simplesamlphp-saml2_1 FEDORA-2016-b000091725");
  script_tag(name: "summary", value: "Check the version of php-simplesamlphp-saml2_1");

  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "A PHP library for SAML2 related
  functionality. Extracted from SimpleSAMLphp [1], used by OpenConext [2].
  This library started as a collaboration between UNINETT [3] and SURFnet
  [4] but everyone is invited to contribute.

  Autoloader: /usr/share/php/SAML2_1/autoload.php

  [1] <a href='https://www.simplesamlphp.org/'
  rel='nofollow'>https://www.simplesamlphp.org/</a>
  [2] <a href='https://www.openconext.org/'
  rel='nofollow'>https://www.openconext.org/</a>
  [3] <a href='https://www.uninett.no/'
  rel='nofollow'>https://www.uninett.no/</a>
  [4] <a href='https://www.surfnet.nl/'
  rel='nofollow'>https://www.surfnet.nl/</a>");

  script_tag(name: "affected", value: "php-simplesamlphp-saml2_1 on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2016-b000091725");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/R2HQI7EYV7IB4TZYY7M4ZOMB4ND2YZWW");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"php-simplesamlphp-saml2_1", rpm:"php-simplesamlphp-saml2_1~1.10.3~1.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
