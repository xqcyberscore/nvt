###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for netpbm CESA-2011:1811 centos4 x86_64
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
tag_insight = "The netpbm packages contain a library of functions which support programs
  for handling various graphics file formats, including .pbm (Portable Bit
  Map), .pgm (Portable Gray Map), .pnm (Portable Any Map), .ppm (Portable
  Pixel Map), and others.

  Two heap-based buffer overflow flaws were found in the embedded JasPer
  library, which is used to provide support for Part 1 of the JPEG 2000 image
  compression standard in the jpeg2ktopam and pamtojpeg2k tools. An attacker
  could create a malicious JPEG 2000 compressed image file that could cause
  jpeg2ktopam to crash or, potentially, execute arbitrary code with the
  privileges of the user running jpeg2ktopam. These flaws do not affect
  pamtojpeg2k. (CVE-2011-4516, CVE-2011-4517)
  
  A stack-based buffer overflow flaw was found in the way the xpmtoppm tool
  processed X PixMap (XPM) image files. An attacker could create a malicious
  XPM file that would cause xpmtoppm to crash or, potentially, execute
  arbitrary code with the privileges of the user running xpmtoppm.
  (CVE-2009-4274)
  
  Red Hat would like to thank Jonathan Foote of the CERT Coordination Center
  for reporting the CVE-2011-4516 and CVE-2011-4517 issues.
  
  All users of netpbm are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.";

tag_affected = "netpbm on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-December/018322.html");
  script_id(881359);
  script_version("$Revision: 8285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 07:29:16 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:35:20 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-4274", "CVE-2011-4516", "CVE-2011-4517");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2011:1811");
  script_name("CentOS Update for netpbm CESA-2011:1811 centos4 x86_64");

  script_tag(name: "summary" , value: "Check for the Version of netpbm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.35.58~8.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.35.58~8.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.35.58~8.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
