###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_373bbbd408_nodejs-uri-js_fc28.nasl 10597 2018-07-25 05:30:00Z cfischer $
#
# Fedora Update for nodejs-uri-js FEDORA-2018-373bbbd408
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
  script_oid("1.3.6.1.4.1.25623.1.0.874686");
  script_version("$Revision: 10597 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 07:30:00 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-17 06:05:58 +0200 (Sun, 17 Jun 2018)");
  script_cve_id("CVE-2017-16021");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nodejs-uri-js FEDORA-2018-373bbbd408");
  script_tag(name:"summary", value:"Check the version of nodejs-uri-js");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"URI.js is an RFC 3986 compliant, scheme 
extendable URI parsing/validating/resolving library for all JavaScript
environments (browsers, Node.js, etc).
");
  script_tag(name:"affected", value:"nodejs-uri-js on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-373bbbd408");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K6Q3JZ4JQ7BCJNI2YJBL2BNZR64DZP3E");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"nodejs-uri-js", rpm:"nodejs-uri-js~4.2.2~2.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
