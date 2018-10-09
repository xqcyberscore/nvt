###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_f1ca41a1a6_php-tcpdf_fc28.nasl 11789 2018-10-09 08:34:17Z santu $
#
# Fedora Update for php-tcpdf FEDORA-2018-f1ca41a1a6
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
  script_oid("1.3.6.1.4.1.25623.1.0.875138");
  script_version("$Revision: 11789 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 10:34:17 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-05 08:39:51 +0200 (Fri, 05 Oct 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for php-tcpdf FEDORA-2018-f1ca41a1a6");
  script_tag(name:"summary", value:"Check the version of php-tcpdf");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"PHP class for generating PDF documents.

* no external libraries are required for the basic functions
* all standard page formats, custom page formats, custom margins and units
  of measure
* UTF-8 Unicode and Right-To-Left languages
* TrueTypeUnicode, OpenTypeUnicode, TrueType, OpenType, Type1 and CID-0 fonts
* font subsetting
* methods to publish some XHTML + CSS code, Javascript and Forms
* images, graphic (geometric figures) and transformation methods
* supports JPEG, PNG and SVG images natively, all images supported by GD
  (GD, GD2, GD2PART, GIF, JPEG, PNG, BMP, XBM, XPM) and all images supported
  via ImagMagick.
* 1D and 2D barcodes: CODE 39, ANSI MH10.8M-1983, USD-3, 3 of 9, CODE 93,
  USS-93, Standard 2 of 5, Interleaved 2 of 5, CODE 128 A/B/C, 2 and 5 Digits
  UPC-Based Extension, EAN 8, EAN 13, UPC-A, UPC-E, MSI, POSTNET, PLANET,
  RMS4CC (Royal Mail 4-state Customer Code), CBC (Customer Bar Code),
  KIX (Klant index - Customer index), Intelligent Mail Barcode, Onecode,
  USPS-B-3200, CODABAR, CODE 11, PHARMACODE, PHARMACODE TWO-TRACKS,
  Datamatrix ECC200, QR-Code, PDF417
* ICC Color Profiles, Grayscale, RGB, CMYK, Spot Colors and Transparencies
* automatic page header and footer management
* document encryption up to 256 bit and digital signature certifications
* transactions to UNDO commands
* PDF annotations, including links, text and file attachments
* text rendering modes (fill, stroke and clipping)
* multiple columns mode
* no-write page regions
* bookmarks and table of content
* text hyphenation
* text stretching and spacing (tracking/kerning)
* automatic page break, line break and text alignments including justification
* automatic page numbering and page groups
* move and delete pages
* page compression (requires php-zlib extension)
* XOBject templates
* PDF/A-1b (ISO 19005-1:2005) support.

By default, TCPDF uses the GD library which is know as slower than ImageMagick
solution. You can optionally install php-pecl-imagick  TCPDF will use it.
");
  script_tag(name:"affected", value:"php-tcpdf on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-f1ca41a1a6");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FJUTX5VPURQMG5ASQPXLKGNM35CUD2XO");
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

  if ((res = isrpmvuln(pkg:"php-tcpdf", rpm:"php-tcpdf~6.2.25~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
