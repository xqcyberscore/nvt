###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for argyllcms FEDORA-2012-6529
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The Argyll color management system supports accurate ICC profile creation for
  acquisition devices, CMYK printers, film recorders and calibration and profiling
  of displays.

  Spectral sample data is supported, allowing a selection of illuminants observer
  types, and paper fluorescent whitener additive compensation. Profiles can also
  incorporate source specific gamut mappings for perceptual and saturation
  intents. Gamut mapping and profile linking uses the CIECAM02 appearance model,
  a unique gamut mapping algorithm, and a wide selection of rendering intents. It
  also includes code for the fastest portable 8 bit raster color conversion
  engine available anywhere, as well as support for fast, fully accurate 16 bit
  conversion. Device color gamuts can also be viewed and compared using a VRML
  viewer.";

tag_affected = "argyllcms on Fedora 16";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2012-May/079762.html");
  script_id(864222);
  script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version("$Revision: 8249 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 07:29:56 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-05-08 12:35:10 +0530 (Tue, 08 May 2012)");
  script_cve_id("CVE-2012-1616");
  script_xref(name: "FEDORA", value: "2012-6529");
  script_name("Fedora Update for argyllcms FEDORA-2012-6529");

  script_tag(name: "summary" , value: "Check for the Version of argyllcms");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"argyllcms", rpm:"argyllcms~1.4.0~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
