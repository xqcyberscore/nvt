###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_aadd3c2790_mupdf_fc28.nasl 13147 2019-01-18 11:35:50Z mmartin $
#
# Fedora Update for mupdf FEDORA-2018-aadd3c2790
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
  script_oid("1.3.6.1.4.1.25623.1.0.875395");
  script_version("$Revision: 13147 $");
  script_cve_id("CVE-2018-10289", "CVE-2018-18662", "CVE-2018-16648", "CVE-2018-16647");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 12:35:50 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-11 04:01:58 +0100 (Fri, 11 Jan 2019)");
  script_name("Fedora Update for mupdf FEDORA-2018-aadd3c2790");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-aadd3c2790");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AE5OPLJ2W3B4FAVKGTRGPBG7UDZOLIMZ");

  script_tag(name:"summary", value:"The remote host is missing an update for
  the 'mupdf' package(s) announced via the FEDORA-2018-aadd3c2790 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"MuPDF is a lightweight PDF viewer and toolkit
  written in portable C. The renderer in MuPDF is tailored for high quality
  anti-aliasedgraphics.  MuPDF renders text with metrics and spacing accurate to
  within fractions of a pixel for the highest fidelity in reproducing the look of
  a printed page on screen. MuPDF has a small footprint.  A binary that includes
  the standard Roman fonts is only one megabyte.  A build with full CJK support
  (including an Asian font) is approximately five megabytes. MuPDF has support for
  all non-interactive PDF 1.7 features, and the toolkit provides a simple API for
  accessing the internal structures of the PDF document.  Example code for
  navigating interactive links and bookmarks, encrypting PDF files, extracting
  fonts, images, and searchable text, and rendering pages to image files is provided.
");

  script_tag(name:"affected", value:"mupdf on Fedora 28.");

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

  if ((res = isrpmvuln(pkg:"mupdf", rpm:"mupdf~1.14.0~6.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
