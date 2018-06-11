###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_a3b7c7eb79_PackageKit_fc27.nasl 10148 2018-06-11 03:14:29Z ckuersteiner $
#
# Fedora Update for PackageKit FEDORA-2018-a3b7c7eb79
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
  script_oid("1.3.6.1.4.1.25623.1.0.874407");
  script_version("$Revision: 10148 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-11 05:14:29 +0200 (Mon, 11 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-02 16:59:00 +0530 (Wed, 02 May 2018)");
  script_cve_id("CVE-2018-1106");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for PackageKit FEDORA-2018-a3b7c7eb79");
  script_tag(name: "summary", value: "Check the version of PackageKit");
  script_tag(name: "vuldetect", value: "Checks if a vulnerable version is present on the target host.");
  script_tag(name: "insight", value: "PackageKit is a D-Bus abstraction layer
that allows the session user to manage packages in a secure way using a cross-distro,
cross-architecture API.
");
  script_tag(name: "affected", value: "PackageKit on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-a3b7c7eb79");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KKV6YNZOFKBELKGZMMEWYH7URTFXOMHV");
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

  if ((res = isrpmvuln(pkg:"PackageKit", rpm:"PackageKit~1.1.10~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
