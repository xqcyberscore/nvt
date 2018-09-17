###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_8738f5f4a7_ceph_fc27.nasl 11416 2018-09-17 03:39:26Z ckuersteiner $
#
# Fedora Update for ceph FEDORA-2018-8738f5f4a7
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
  script_oid("1.3.6.1.4.1.25623.1.0.874898");
  script_version("$Revision: 11416 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 05:39:26 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 06:04:25 +0200 (Tue, 07 Aug 2018)");
  script_cve_id("CVE-2018-1128", "CVE-2018-1129", "CVE-2018-10861");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ceph FEDORA-2018-8738f5f4a7");
  script_tag(name:"summary", value:"Check the version of ceph");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Ceph is a massively scalable, open-source, 
distributed storage system that runs on commodity hardware and delivers object, 
block and file system storage.
");
  script_tag(name:"affected", value:"ceph on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-8738f5f4a7");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YVC5CMLRNFNMIHUGE5ASDO2IV4XEJ67X");
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

  if ((res = isrpmvuln(pkg:"ceph", rpm:"ceph~12.2.7~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
