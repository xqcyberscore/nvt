###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_33fef25ed1_pandoc-citeproc_fc28.nasl 11250 2018-09-06 03:05:29Z ckuersteiner $
#
# Fedora Update for pandoc-citeproc FEDORA-2018-33fef25ed1
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
  script_oid("1.3.6.1.4.1.25623.1.0.875024");
  script_version("$Revision: 11250 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-06 05:05:29 +0200 (Thu, 06 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-01 07:40:46 +0200 (Sat, 01 Sep 2018)");
  script_cve_id("CVE-2018-10773", "CVE-2018-10774", "CVE-2018-10775");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for pandoc-citeproc FEDORA-2018-33fef25ed1");
  script_tag(name:"summary", value:"Check the version of pandoc-citeproc");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"insight", value:"The pandoc-citeproc library exports functions
for using the citeproc system with pandoc. It relies on citeproc-hs, a library
for rendering bibliographic reference citations into a variety of styles using
a macro language called Citation Style Language (CSL). More details on CSL can be
found here:
 'http://citationstyles.org/%3E.'.

Currently this package includes a heavily revised copy of the citeproc-hs code.
When citeproc-hs is updated to be compatible, this package will simply depend
on citeproc-hs.

This package also contains an executable: pandoc-citeproc, which works as a
pandoc filter, and also has a mode for converting bibliographic databases a
YAML format suitable for inclusion in pandoc YAML metadata.
");
  script_tag(name:"affected", value:"pandoc-citeproc on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-33fef25ed1");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FEVYVLYGX4KZFTO3NWIFU665C356HC4G");
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

  if ((res = isrpmvuln(pkg:"pandoc-citeproc", rpm:"pandoc-citeproc~0.12.2.5~4.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
