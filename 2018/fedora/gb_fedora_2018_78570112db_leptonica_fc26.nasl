###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_78570112db_leptonica_fc26.nasl 10012 2018-05-30 03:37:26Z ckuersteiner $
#
# Fedora Update for leptonica FEDORA-2018-78570112db
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
  script_oid("1.3.6.1.4.1.25623.1.0.874213");
  script_version("$Revision: 10012 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 05:37:26 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2018-03-14 08:41:20 +0100 (Wed, 14 Mar 2018)");
  script_cve_id("CVE-2017-18196", "CVE-2018-3836", "CVE-2018-7186", "CVE-2018-7247");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for leptonica FEDORA-2018-78570112db");
  script_tag(name: "summary", value: "Check the version of leptonica");
  script_tag(name: "vuldetect", value: "Checks if a vulnerable version is present on the target host.");
  script_tag(name: "insight", value: "The library supports many operations that
are useful on
 * Document images
 * Natural images

Fundamental image processing and image analysis operations
 * Rasterop (aka bitblt)
 * Affine transforms (scaling, translation, rotation, shear)
   on images of arbitrary pixel depth
 * Projective and bi-linear transforms
 * Binary and gray scale morphology, rank order filters, and
   convolution
 * Seed-fill and connected components
 * Image transformations with changes in pixel depth, both at
   the same scale and with scale change
 * Pixelwise masking, blending, enhancement, arithmetic ops,
   etc.
");
  script_tag(name: "affected", value: "leptonica on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-78570112db");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HQE5K6K6RVMZIFF2TRE5XE74PK53JVPN");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"leptonica", rpm:"leptonica~1.74.4~5.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
