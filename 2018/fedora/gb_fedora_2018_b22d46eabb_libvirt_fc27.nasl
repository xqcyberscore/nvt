###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_b22d46eabb_libvirt_fc27.nasl 9180 2018-03-22 15:38:54Z cfischer $
#
# Fedora Update for libvirt FEDORA-2018-b22d46eabb
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
  script_oid("1.3.6.1.4.1.25623.1.0.874177");
  script_version("$Revision: 9180 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-22 16:38:54 +0100 (Thu, 22 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-02 08:45:56 +0100 (Fri, 02 Mar 2018)");
  script_cve_id("CVE-2018-5748", "CVE-2018-6764");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libvirt FEDORA-2018-b22d46eabb");
  script_tag(name: "summary", value: "Check the version of libvirt");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Libvirt is a C toolkit to interact with 
the virtualization capabilities of recent versions of Linux (and other OSes). 
The main package includes the libvirtd server exporting the virtualization support.
");
  script_tag(name: "affected", value: "libvirt on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-b22d46eabb");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LPTNMXGI5MJKYJIZJJ7WCK2XCEJ4GOZY");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~3.7.0~4.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
