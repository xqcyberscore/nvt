###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_69cce46328_rust_fc27.nasl 11829 2018-10-11 02:52:58Z ckuersteiner $
#
# Fedora Update for rust FEDORA-2018-69cce46328
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
  script_oid("1.3.6.1.4.1.25623.1.0.875150");
  script_version("$Revision: 11829 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-11 04:52:58 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-06 08:44:11 +0200 (Sat, 06 Oct 2018)");
  script_cve_id("CVE-2018-1000622");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for rust FEDORA-2018-69cce46328");
  script_tag(name:"summary", value:"Check the version of rust");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Rust is a systems programming language that
  runs blazingly fast, prevents segfaults, and guarantees thread safety.

This package includes the Rust compiler and documentation generator.
");
  script_tag(name:"affected", value:"rust on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-69cce46328");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KILBUMOSK4LEAMK73UIIPLRTXDJXNLLD");
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

  if ((res = isrpmvuln(pkg:"rust", rpm:"rust~1.29.1~2.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
