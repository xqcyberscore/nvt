###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_3dc16842e2_gnupg2_fc28.nasl 10279 2018-06-21 07:32:57Z santu $
#
# Fedora Update for gnupg2 FEDORA-2018-3dc16842e2
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
  script_oid("1.3.6.1.4.1.25623.1.0.874703");
  script_version("$Revision: 10279 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-21 09:32:57 +0200 (Thu, 21 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 06:13:49 +0200 (Tue, 19 Jun 2018)");
  script_cve_id("CVE-2018-12020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gnupg2 FEDORA-2018-3dc16842e2");
  script_tag(name:"summary", value:"Check the version of gnupg2");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"GnuPG is GNU&#39 s tool for secure communication and data storage.  It can
be used to encrypt data and to create digital signatures.  It includes
an advanced key management facility and is compliant with the proposed
OpenPGP Internet standard as described in RFC2440 and the S/MIME
standard as described by several RFCs.

GnuPG 2.0 is a newer version of GnuPG with additional support for
S/MIME.  It has a different design philosophy that splits
functionality up into several modules. The S/MIME and smartcard functionality
is provided by the gnupg2-smime package.
");
  script_tag(name:"affected", value:"gnupg2 on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-3dc16842e2");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5KLP2VMFOZIELHCJ5HA3HF3IU35SECZP");
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

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.2.8~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}