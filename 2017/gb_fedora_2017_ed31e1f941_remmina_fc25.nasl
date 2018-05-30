###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_ed31e1f941_remmina_fc25.nasl 10012 2018-05-30 03:37:26Z ckuersteiner $
#
# Fedora Update for remmina FEDORA-2017-ed31e1f941
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
  script_oid("1.3.6.1.4.1.25623.1.0.873228");
  script_version("$Revision: 10012 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 05:37:26 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2017-08-08 07:37:08 +0200 (Tue, 08 Aug 2017)");
  script_cve_id("CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839",
                "CVE-2017-2835", "CVE-2017-2834");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for remmina FEDORA-2017-ed31e1f941");
  script_tag(name: "summary", value: "Check the version of remmina");
  script_tag(name: "vuldetect", value: "Checks if a vulnerable version is present on the target host.");
  script_tag(name: "insight", value: "Remmina is a remote desktop client written
in GTK+, aiming to be useful for system administrators and travelers, who need
to work with lots of remote computers in front of either large monitors or
tiny net-books.

Remmina supports multiple network protocols in an integrated and consistent
user interface. Currently RDP, VNC, XDMCP and SSH are supported.

Please don&#39 t forget to install the plugins for the protocols you want to use.
");
  script_tag(name: "affected", value: "remmina on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-ed31e1f941");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GFS76PWXKNQOPXHRXM2C5Y7GBFFYUMO4");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"remmina", rpm:"remmina~1.2.0~0.39.20170724git0387ee0.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
