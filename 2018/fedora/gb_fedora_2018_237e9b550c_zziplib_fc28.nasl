###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_237e9b550c_zziplib_fc28.nasl 10778 2018-08-06 02:57:15Z ckuersteiner $
#
# Fedora Update for zziplib FEDORA-2018-237e9b550c
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
  script_oid("1.3.6.1.4.1.25623.1.0.874880");
  script_version("$Revision: 10778 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 04:57:15 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-02 06:04:25 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2018-6541", "CVE-2018-7727", "CVE-2017-5974", "CVE-2017-5975", 
                "CVE-2017-5976", "CVE-2017-5977", "CVE-2017-5978", "CVE-2017-5979", 
                "CVE-2017-5980", "CVE-2017-5981", "CVE-2018-7726");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for zziplib FEDORA-2018-237e9b550c");
  script_tag(name:"summary", value:"Check the version of zziplib");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"The zziplib library is intentionally lightweight, 
it offers the ability to easily extract data from files archived in a single zip 
file. Applications can bundle files into a single zip archive and access them. 
The implementation is based only on the (free) subset of compression with the zlib 
algorithm which is actually used by the zip/unzip tools.
");
  script_tag(name:"affected", value:"zziplib on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-237e9b550c");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I6J523IVLVVPUEHRDYT54A5QOKM5XVTO");
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

  if ((res = isrpmvuln(pkg:"zziplib", rpm:"zziplib~0.13.69~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
