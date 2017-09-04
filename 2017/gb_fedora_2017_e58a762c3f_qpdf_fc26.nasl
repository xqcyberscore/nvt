###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_e58a762c3f_qpdf_fc26.nasl 6990 2017-08-23 08:40:32Z asteins $
#
# Fedora Update for qpdf FEDORA-2017-e58a762c3f
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
  script_oid("1.3.6.1.4.1.25623.1.0.873219");
  script_version("$Revision: 6990 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 10:40:32 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-07 07:40:25 +0200 (Mon, 07 Aug 2017)");
  script_cve_id("CVE-2017-11627", "CVE-2017-11626", "CVE-2017-11625", "CVE-2017-11624", 
                "CVE-2017-9208", "CVE-2017-9209", "CVE-2017-9210");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qpdf FEDORA-2017-e58a762c3f");
  script_tag(name: "summary", value: "Check the version of qpdf");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "QPDF is a command-line program that does 
structural, content-preserving transformations on PDF files. It could have been 
called something like pdf-to-pdf. It includes support for merging and splitting PDFs
and to manipulate the list of pages in a PDF file. It is not a PDF viewer
or a program capable of converting PDF into other formats.
");
  script_tag(name: "affected", value: "qpdf on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-e58a762c3f");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RDER22UZHGCCNSH52ALTIPF4W6YKQKBP");
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

  if ((res = isrpmvuln(pkg:"qpdf", rpm:"qpdf~6.0.0~6.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
