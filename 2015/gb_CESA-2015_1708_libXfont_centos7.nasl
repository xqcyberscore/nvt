###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libXfont CESA-2015:1708 centos7 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882276");
  script_version("$Revision: 6657 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:50:44 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-09-04 08:14:55 +0200 (Fri, 04 Sep 2015)");
  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libXfont CESA-2015:1708 centos7 ");
  script_tag(name: "summary", value: "Check the version of libXfont");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The libXfont package provides the X.Org libXfont runtime library. X.Org is
an open source implementation of the X Window System.

An integer overflow flaw was found in the way libXfont processed certain
Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local user could
use this flaw to crash the X.Org server or, potentially, execute arbitrary
code with the privileges of the X.Org server. (CVE-2015-1802)

An integer truncation flaw was discovered in the way libXfont processed
certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious, local
user could use this flaw to crash the X.Org server or, potentially, execute
arbitrary code with the privileges of the X.Org server. (CVE-2015-1804)

A NULL pointer dereference flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts.
A malicious, local user could use this flaw to crash the X.Org server.
(CVE-2015-1803)

All libXfont users are advised to upgrade to this updated package, which
contains backported patches to correct these issues.
");
  script_tag(name: "affected", value: "libXfont on CentOS 7");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "CESA", value: "2015:1708");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2015-September/021371.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.7~3.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-devel", rpm:"libXfont-devel~1.4.7~3.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
