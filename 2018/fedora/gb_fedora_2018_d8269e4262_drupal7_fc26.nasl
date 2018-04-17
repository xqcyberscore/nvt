###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_d8269e4262_drupal7_fc26.nasl 9499 2018-04-17 03:38:12Z ckuersteiner $
#
# Fedora Update for drupal7 FEDORA-2018-d8269e4262
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
  script_oid("1.3.6.1.4.1.25623.1.0.874358");
  script_version("$Revision: 9499 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-17 05:38:12 +0200 (Tue, 17 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-11 15:28:12 +0200 (Wed, 11 Apr 2018)");
  script_cve_id("CVE-2017-6926", "CVE-2017-6927", "CVE-2017-6928", "CVE-2017-6929", 
                "CVE-2017-6930", "CVE-2017-6931", "CVE-2017-6932");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for drupal7 FEDORA-2018-d8269e4262");
  script_tag(name: "summary", value: "Check the version of drupal7");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Equipped with a powerful blend of features, 
Drupal is a Content Management System written in PHP that can support a variety 
of websites ranging from personal weblogs to large community-driven websites.  
Drupal is highly configurable, skinnable, and secure.
");
  script_tag(name: "affected", value: "drupal7 on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-d8269e4262");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I4N63W35VZ32IRMETFSYB5PQOWCWARYH");
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

  if ((res = isrpmvuln(pkg:"drupal7", rpm:"drupal7~7.58~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
