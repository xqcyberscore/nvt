###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_2c9852dd05_liblouis_fc26.nasl 7920 2017-11-28 07:49:35Z asteins $
#
# Fedora Update for liblouis FEDORA-2017-2c9852dd05
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873688");
  script_version("$Revision: 7920 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-28 08:49:35 +0100 (Tue, 28 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:07:31 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-13738", "CVE-2017-13739", "CVE-2017-13740", "CVE-2017-13741", 
                "CVE-2017-13742", "CVE-2017-13743", "CVE-2017-13744");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for liblouis FEDORA-2017-2c9852dd05");
  script_tag(name: "summary", value: "Check the version of liblouis");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Liblouis is an open-source braille translator 
and back-translator named in honor of Louis Braille. It features support for 
computer and literary braille, supports contracted and uncontracted translation 
for many languages and has support for hyphenation. New languages can easily be 
added through tables that support a rule- or dictionary based approach. Liblouis 
also supports math braille (Nemeth and Marburg).

Liblouis has features to support screen-reading programs. This has led to its
use in two open-source screen readers, NVDA and Orca. It is also used in some
commercial assistive technology applications for example by ViewPlus.

Liblouis is based on the translation routines in the BRLTTY screen reader for
Linux. It has, however, gone far beyond these routines.
");
  script_tag(name: "affected", value: "liblouis on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-2c9852dd05");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/PB5RNRFGI6HZN6VFOFGNA5YPMMX5WOZA");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"liblouis", rpm:"liblouis~2.6.2~12.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
