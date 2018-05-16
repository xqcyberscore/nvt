###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_3fc05e009d_gnupg2_fc27.nasl 9860 2018-05-16 09:27:39Z asteins $
#
# Fedora Update for gnupg2 FEDORA-2018-3fc05e009d
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
  script_oid("1.3.6.1.4.1.25623.1.0.874364");
  script_version("$Revision: 9860 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-16 11:27:39 +0200 (Wed, 16 May 2018) $");
  script_tag(name:"creation_date", value:"2018-04-16 09:33:48 +0200 (Mon, 16 Apr 2018)");
  script_cve_id("CVE-2018-9234");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for gnupg2 FEDORA-2018-3fc05e009d");
  script_tag(name: "summary", value: "Check the version of gnupg2");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GnuPG is GNU&#39 s tool for secure 
communication and data storage.  It can be used to encrypt data and to create 
digital signatures.  It includes an advanced key management facility and is 
compliant with the proposed OpenPGP Internet standard as described in RFC2440 
and the S/MIME standard as described by several RFCs.

GnuPG 2.0 is a newer version of GnuPG with additional support for
S/MIME.  It has a different design philosophy that splits
functionality up into several modules. The S/MIME and smartcard functionality
is provided by the gnupg2-smime package.
");
  script_tag(name: "affected", value: "gnupg2 on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-3fc05e009d");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PE2H5PQVOHCUH7XQVYYIK2HVOG63WSHH");
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

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.2.6~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
