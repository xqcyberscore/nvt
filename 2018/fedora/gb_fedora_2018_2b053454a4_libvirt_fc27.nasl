###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_2b053454a4_libvirt_fc27.nasl 10778 2018-08-06 02:57:15Z ckuersteiner $
#
# Fedora Update for libvirt FEDORA-2018-2b053454a4
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
  script_oid("1.3.6.1.4.1.25623.1.0.874871");
  script_version("$Revision: 10778 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 04:57:15 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-02 06:01:22 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2017-5715", "CVE-2018-3639", "CVE-2018-5748", "CVE-2018-6764", 
                "CVE-2017-1000256");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libvirt FEDORA-2018-2b053454a4");
  script_tag(name:"summary", value:"Check the version of libvirt");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Libvirt is a C toolkit to interact with the 
virtualization capabilities of recent versions of Linux (and other OSes). 
The main package includes the libvirtd server exporting the virtualization support.
");
  script_tag(name:"affected", value:"libvirt on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-2b053454a4");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K6UO5GVWH3VTHRNSE7JAMS6D64LCRSHH");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~3.7.0~6.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
