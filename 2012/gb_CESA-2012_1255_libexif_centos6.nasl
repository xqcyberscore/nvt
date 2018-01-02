###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libexif CESA-2012:1255 centos6 
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
tag_insight = "The libexif packages provide an Exchangeable image file format (Exif)
  library. Exif allows metadata to be added to and read from certain types
  of image files.

  Multiple flaws were found in the way libexif processed Exif tags. An
  attacker could create a specially-crafted image file that, when opened in
  an application linked against libexif, could cause the application to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2012-2812, CVE-2012-2813, CVE-2012-2814,
  CVE-2012-2836, CVE-2012-2837, CVE-2012-2840, CVE-2012-2841)
  
  Red Hat would like to thank Dan Fandrich for reporting these issues.
  Upstream acknowledges Mateusz Jurczyk of the Google Security Team as the
  original reporter of CVE-2012-2812, CVE-2012-2813, and CVE-2012-2814; and
  Yunho Kim as the original reporter of CVE-2012-2836 and CVE-2012-2837.
  
  Users of libexif are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. All running
  applications linked against libexif must be restarted for the update to
  take effect.";

tag_affected = "libexif on CentOS 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2012-September/018863.html");
  script_id(881488);
  script_version("$Revision: 8265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-01 07:29:23 +0100 (Mon, 01 Jan 2018) $");
  script_tag(name:"creation_date", value:"2012-09-17 16:43:17 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836",
                "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2012:1255");
  script_name("CentOS Update for libexif CESA-2012:1255 centos6 ");

  script_tag(name: "summary" , value: "Check for the Version of libexif");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libexif", rpm:"libexif~0.6.21~5.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libexif-devel", rpm:"libexif-devel~0.6.21~5.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
