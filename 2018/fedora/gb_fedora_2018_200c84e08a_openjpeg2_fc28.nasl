###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_200c84e08a_openjpeg2_fc28.nasl 12917 2019-01-01 16:12:40Z cfischer $
#
# Fedora Update for openjpeg2 FEDORA-2018-200c84e08a
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.875384");
  script_version("$Revision: 12917 $");
  script_cve_id("CVE-2018-18088", "CVE-2018-6616", "CVE-2018-5785");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-01-01 17:12:40 +0100 (Tue, 01 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-12-29 04:31:19 +0100 (Sat, 29 Dec 2018)");
  script_name("Fedora Update for openjpeg2 FEDORA-2018-200c84e08a");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-200c84e08a");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AUTLQIW5AF3YHUK3XFZWXCN5N4WPNIXV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2'
  package(s) announced via the FEDORA-2018-200c84e08a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The OpenJPEG library is an open-source JPEG 2000 library developed in order to
promote the use of JPEG 2000.

This package contains
* JPEG 2000 codec compliant with the Part 1 of the standard (Class-1 Profile-1
  compliance).
* JP2 (JPEG 2000 standard Part 2 - Handling of JP2 boxes and extended multiple
  component transforms for multispectral and hyperspectral imagery)
");

  script_tag(name:"affected", value:"openjpeg2 on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~10.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
