###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_4897772a43_libvncserver_fc27.nasl 9271 2018-03-31 07:25:25Z cfischer $
#
# Fedora Update for libvncserver FEDORA-2018-4897772a43
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
  script_oid("1.3.6.1.4.1.25623.1.0.874285");
  script_version("$Revision: 9271 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-31 09:25:25 +0200 (Sat, 31 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-28 08:58:22 +0200 (Wed, 28 Mar 2018)");
  script_cve_id("CVE-2018-7225");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libvncserver FEDORA-2018-4897772a43");
  script_tag(name: "summary", value: "Check the version of libvncserver");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "LibVNCServer makes writing a VNC server 
(or more correctly, a program exporting a frame-buffer via the Remote Frame 
Buffer protocol) easy.

It hides the programmer from the tedious task of managing clients and
compression schemata.
");
  script_tag(name: "affected", value: "libvncserver on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-4897772a43");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YYNK6ZTW4QSUNWBL3YCZXRC3QMHW7FZK");
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

  if ((res = isrpmvuln(pkg:"libvncserver", rpm:"libvncserver~0.9.11~5.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
