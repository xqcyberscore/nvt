###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_a4e13742b4_gnupg_fc28.nasl 10279 2018-06-21 07:32:57Z santu $
#
# Fedora Update for gnupg FEDORA-2018-a4e13742b4
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
  script_oid("1.3.6.1.4.1.25623.1.0.874711");
  script_version("$Revision: 10279 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-21 09:32:57 +0200 (Thu, 21 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-20 06:21:22 +0200 (Wed, 20 Jun 2018)");
  script_cve_id("CVE-2018-12020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gnupg FEDORA-2018-a4e13742b4");
  script_tag(name:"summary", value:"Check the version of gnupg");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"GnuPG (GNU Privacy Guard) is a GNU utility for encrypting data and
creating digital signatures. GnuPG has advanced key management
capabilities and is compliant with the proposed OpenPGP Internet
standard described in RFC2440. Since GnuPG doesn&#39 t use any patented
algorithm, it is not compatible with any version of PGP2 (PGP2.x uses
only IDEA for symmetric-key encryption, which is patented worldwide).
");
  script_tag(name:"affected", value:"gnupg on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-a4e13742b4");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TM65JCD6SYPGZS3OXVWSM5K44DMQJKSE");
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

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.23~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}