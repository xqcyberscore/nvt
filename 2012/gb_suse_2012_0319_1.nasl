###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0319_1.nasl 8245 2017-12-26 06:29:59Z teissa $
#
# SuSE Update for libvorbis openSUSE-SU-2012:0319-1 (libvorbis)
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
tag_affected = "libvorbis on openSUSE 11.4";
tag_insight = "Specially crafted ogg files could cause a heap-based buffer
  overflow in the vorbis audio compression library that could
  potentially be exploited by attackers to cause a crash or
  execute arbitrary code (CVE-2012-0444).";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_id(850232);
  script_version("$Revision: 8245 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 07:29:59 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-08-02 22:27:44 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2012-0444");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "openSUSE-SU", value: "2012:0319_1");
  script_name("SuSE Update for libvorbis openSUSE-SU-2012:0319-1 (libvorbis)");

  script_tag(name: "summary" , value: "Check for the Version of libvorbis");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbis0-32bit", rpm:"libvorbis0-32bit~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbisenc2-32bit", rpm:"libvorbisenc2-32bit~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbisfile3-32bit", rpm:"libvorbisfile3-32bit~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbis-doc", rpm:"libvorbis-doc~1.3.2~6.7.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
