###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_b52f851dea_calamares_fc26.nasl 7943 2017-11-30 11:54:54Z santu $
#
# Fedora Update for calamares FEDORA-2017-b52f851dea
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873804");
  script_version("$Revision: 7943 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-30 12:54:54 +0100 (Thu, 30 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-26 07:58:14 +0100 (Sun, 26 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for calamares FEDORA-2017-b52f851dea");
  script_tag(name: "summary", value: "Check the version of calamares");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Calamares is a distribution-independent 
installer framework, designed to install from a live CD/DVD/USB environment to 
a hard disk. It includes a graphical installation program based on Qt 5. This 
package includes the Calamares framework and the required configuration files 
to produce a working replacement for Anaconda&#39 s liveinst.
");
  script_tag(name: "affected", value: "calamares on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-b52f851dea");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VNXPOZQOKG5FKCZTOWMYM6KCN2ZYCDZ7");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"calamares", rpm:"calamares~3.1.8~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
