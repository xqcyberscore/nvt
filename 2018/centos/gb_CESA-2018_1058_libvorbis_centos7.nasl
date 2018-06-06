###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1058_libvorbis_centos7.nasl 10076 2018-06-05 08:44:03Z santu $
#
# CentOS Update for libvorbis CESA-2018:1058 centos7 
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
  script_oid("1.3.6.1.4.1.25623.1.0.882902");
  script_version("$Revision: 10076 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-05 10:44:03 +0200 (Tue, 05 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-05 14:03:31 +0530 (Tue, 05 Jun 2018)");
  script_cve_id("CVE-2018-5146");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libvorbis CESA-2018:1058 centos7 ");
  script_tag(name:"summary", value:"Check the version of libvorbis");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libvorbis package contains runtime libraries for use in programs that
support Ogg Vorbis, a fully open, non-proprietary, patent- and
royalty-free, general-purpose compressed format for audio and music at
fixed and variable bitrates.

Security Fix(es):

* Mozilla: Vorbis audio processing out of bounds write (MFSA 2018-08)
(CVE-2018-5146)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla Project for reporting this issue.
Upstream acknowledges Richard Zhu via Trend Micro's Zero Day Initiative as
the original reporter.
");
  script_tag(name:"affected", value:"libvorbis on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:1058");
  script_xref(name:"URL" , value:"http://lists.centos.org/pipermail/centos-announce/2018-May/022878.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.3.3~8.el7.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.3.3~8.el7.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvorbis-devel-docs", rpm:"libvorbis-devel-docs~1.3.3~8.el7.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}