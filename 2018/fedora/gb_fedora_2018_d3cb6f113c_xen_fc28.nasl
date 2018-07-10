###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_d3cb6f113c_xen_fc28.nasl 10423 2018-07-05 13:03:28Z santu $
#
# Fedora Update for xen FEDORA-2018-d3cb6f113c
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
  script_oid("1.3.6.1.4.1.25623.1.0.874755");
  script_version("$Revision: 10423 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-05 15:03:28 +0200 (Thu, 05 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-30 06:02:58 +0200 (Sat, 30 Jun 2018)");
  script_cve_id("CVE-2018-3665", "CVE-2018-3639", "CVE-2018-8897", "CVE-2018-10982", 
                "CVE-2018-10981", "CVE-2018-10472", "CVE-2018-10471");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for xen FEDORA-2018-d3cb6f113c");
  script_tag(name:"summary", value:"Check the version of xen");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"This package contains the XenD daemon and xm 
command line tools, needed to manage virtual machines running under the Xen 
hypervisor
");
  script_tag(name:"affected", value:"xen on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-d3cb6f113c");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ALMLZ3SKTV3RRHYNXOE5J7YVGWZZ2O4C");
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

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.10.1~4.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
