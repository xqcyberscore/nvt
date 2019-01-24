###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2019_e70c729d8a_gnupg2_fc28.nasl 13245 2019-01-23 14:22:53Z santu $
#
# Fedora Update for gnupg2 FEDORA-2019-e70c729d8a
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.875425");
  script_version("$Revision: 13245 $");
  script_cve_id("CVE-2018-1000858");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 15:22:53 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-22 04:06:25 +0100 (Tue, 22 Jan 2019)");
  script_name("Fedora Update for gnupg2 FEDORA-2019-e70c729d8a");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2019-e70c729d8a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EU2NDWRZ6CKOQAG2I5CX2C3PVHUWXJRZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the
  'gnupg2' package(s) announced via the FEDORA-2019-e70c729d8a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"GnuPG is GNU&#39 s tool for secure communication
  and data storage.  It can be used to encrypt data and to create digital signatures.
  It includes an advanced key management facility and is compliant with the proposed
  OpenPGP Internet standard as described in RFC2440 and the S/MIME standard as described
  by several RFCs.

GnuPG 2.0 is a newer version of GnuPG with additional support for
S/MIME.  It has a different design philosophy that splits
functionality up into several modules. The S/MIME and smartcard functionality
is provided by the gnupg2-smime package.
");

  script_tag(name:"affected", value:"gnupg2 on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.2.12~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
