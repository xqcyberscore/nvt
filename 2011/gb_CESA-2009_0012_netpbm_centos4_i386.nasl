###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for netpbm CESA-2009:0012 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The netpbm package contains a library of functions for editing and
  converting between various graphics file formats, including .pbm (portable
  bitmaps), .pgm (portable graymaps), .pnm (portable anymaps), .ppm (portable
  pixmaps), and others.

  An input validation flaw and multiple integer overflows were discovered in
  the JasPer library providing support for JPEG-2000 image format and used in
  the jpeg2ktopam and pamtojpeg2k converters. An attacker could create a
  carefully-crafted JPEG file which could cause jpeg2ktopam to crash or,
  possibly, execute arbitrary code as the user running jpeg2ktopam.
  (CVE-2007-2721, CVE-2008-3520)
  
  All users are advised to upgrade to these updated packages which contain
  backported patches which resolve these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "netpbm on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-February/015631.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880774");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "CESA", value: "2009:0012");
  script_cve_id("CVE-2007-2721", "CVE-2008-3520");
  script_name("CentOS Update for netpbm CESA-2009:0012 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of netpbm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

  if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.25~2.1.el4.4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.25~2.1.el4.4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.25~2.1.el4.4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
