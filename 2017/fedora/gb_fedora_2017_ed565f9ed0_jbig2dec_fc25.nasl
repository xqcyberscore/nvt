###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_ed565f9ed0_jbig2dec_fc25.nasl 7990 2017-12-05 07:08:14Z asteins $
#
# Fedora Update for jbig2dec FEDORA-2017-ed565f9ed0
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
  script_oid("1.3.6.1.4.1.25623.1.0.873843");
  script_version("$Revision: 7990 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-05 08:08:14 +0100 (Tue, 05 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-04 18:48:37 +0530 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2017-9216");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for jbig2dec FEDORA-2017-ed565f9ed0");
  script_tag(name: "summary", value: "Check the version of jbig2dec");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "jbig2dec is a decoder implementation of the 
JBIG2 image compression format. JBIG2 is designed for lossy or lossless encoding 
of &#39 bilevel&#39  (1-bit monochrome) images at moderately high resolution, 
and in particular scanned paper documents. In this domain it is very efficient, 
offering compression ratios on the order of 100:1.");
  script_tag(name: "affected", value: "jbig2dec on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-ed565f9ed0");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OTY5MIWRC6GEGLAIUDAFMIAE67HTQBFB");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"jbig2dec", rpm:"jbig2dec~0.14~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
