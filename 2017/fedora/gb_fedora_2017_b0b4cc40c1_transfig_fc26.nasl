###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_b0b4cc40c1_transfig_fc26.nasl 8118 2017-12-14 08:01:12Z asteins $
#
# Fedora Update for transfig FEDORA-2017-b0b4cc40c1
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
  script_oid("1.3.6.1.4.1.25623.1.0.873870");
  script_version("$Revision: 8118 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-14 09:01:12 +0100 (Thu, 14 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-10 08:10:05 +0100 (Sun, 10 Dec 2017)");
  script_cve_id("CVE-2017-16899");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for transfig FEDORA-2017-b0b4cc40c1");
  script_tag(name: "summary", value: "Check the version of transfig");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The transfig utility creates a makefile 
which translates FIG (created by xfig) or PIC figures into a specified LaTeX 
graphics language (for example, PostScript(TM)).  Transfig is used to create 
TeX documents which are portable (i.e., they can be printed in a wide variety of
environments).

Install transfig if you need a utility for translating FIG or PIC
figures into certain graphics languages.
");
  script_tag(name: "affected", value: "transfig on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-b0b4cc40c1");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MCUENJQNHVYLROFSXJPDPPHHAYFYM3Z2");
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

  if ((res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.6a~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
