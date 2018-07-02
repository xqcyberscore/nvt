###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_049dee041d_mupdf_fc28.nasl 10374 2018-07-02 04:44:41Z asteins $
#
# Fedora Update for mupdf FEDORA-2018-049dee041d
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
  script_oid("1.3.6.1.4.1.25623.1.0.874752");
  script_version("$Revision: 10374 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-02 06:44:41 +0200 (Mon, 02 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-06-29 11:00:33 +0200 (Fri, 29 Jun 2018)");
  script_cve_id("CVE-2018-10289");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mupdf FEDORA-2018-049dee041d");
  script_tag(name:"summary", value:"Check the version of mupdf");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"MuPDF is a lightweight PDF viewer and toolkit 
written in portable C. The renderer in MuPDF is tailored for high quality 
anti-aliased graphics.  MuPDF renders text with metrics and spacing accurate to
within fractions of a pixel for the highest fidelity in reproducing the look of 
a printed page on screen. MuPDF has a small footprint.  A binary that includes 
the standard Roman fonts is only one megabyte.  A build with full CJK support
(including an Asian font) is approximately five megabytes. MuPDF has support 
for all non-interactive PDF 1.7 features, and the toolkit provides a simple 
API for accessing the internal structures of the PDF document.  Example code 
for navigating interactive links and bookmarks, encrypting PDF files, extracting 
fonts, images, and searchable text, and rendering pages to image files is provided.
");
  script_tag(name:"affected", value:"mupdf on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-049dee041d");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HJD2SWR5MW54TLI46JD5FBBOOGTKKUWK");
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

  if ((res = isrpmvuln(pkg:"mupdf", rpm:"mupdf~1.13.0~8.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
