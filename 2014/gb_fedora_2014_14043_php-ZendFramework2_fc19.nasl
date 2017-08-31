###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-ZendFramework2 FEDORA-2014-14043
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.868470");
  script_version("$Revision: 6715 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-11-11 06:21:33 +0100 (Tue, 11 Nov 2014)");
  script_cve_id("CVE-2014-8088", "CVE-2014-8089");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Fedora Update for php-ZendFramework2 FEDORA-2014-14043");
  script_tag(name: "summary", value: "Check the version of php-ZendFramework2");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Zend Framework 2 is an open source framework for developing web applications
and services using PHP 5.3+. Zend Framework 2 uses 100% object-oriented code
and utilizes most of the new features of PHP 5.3, namely namespaces, late
static binding, lambda functions and closures.

Zend Framework 2 evolved from Zend Framework 1, a successful PHP framework
with over 15 million downloads.

Note: This meta package installs all base Zend Framework component packages
(Authentication, Barcode, Cache, Captcha, Code, Config, Console, Crypt, Db,
Debug, Di, Dom, Escaper, EventManager, Feed, File, Filter, Form, Http, I18n,
InputFilter, Json, Ldap, Loader, Log, Mail, Math, Memory, Mime, ModuleManager,
Mvc, Navigation, Paginator, Permissions-Acl, Permissions-Rbac, ProgressBar,
Serializer, Server, ServiceManager, Session, Soap, Stdlib, Tag, Test, Text,
Uri, Validator, Version, View, XmlRpc) except the optional Cache-apc and
Cache-memcached packages.
");
  script_tag(name: "affected", value: "php-ZendFramework2 on Fedora 19");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "FEDORA", value: "2014-14043");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-November/143323.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(release == "FC19")
{

  if ((res = isrpmvuln(pkg:"php-ZendFramework2", rpm:"php-ZendFramework2~2.2.8~2.fc19", rls:"FC19")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}