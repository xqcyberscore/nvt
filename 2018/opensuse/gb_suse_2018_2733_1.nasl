###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2733_1.nasl 11565 2018-09-24 08:00:39Z santu $
#
# SuSE Update for okular openSUSE-SU-2018:2733-1 (okular)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851893");
  script_version("$Revision: 11565 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-24 10:00:39 +0200 (Mon, 24 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-16 07:52:36 +0200 (Sun, 16 Sep 2018)");
  script_cve_id("CVE-2018-1000801");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for okular openSUSE-SU-2018:2733-1 (okular)");
  script_tag(name:"summary", value:"Check the version of okular");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"
  This update for okular fixes the following security issue:

  - CVE-2018-1000801: Prevent directory traversal vulnerability in function
  unpackDocumentArchive could have resulted in arbitrary file creation via
  a specially crafted Okular archive (bsc#1107591).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1006=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1006=1");
  script_tag(name:"affected", value:"okular on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:2733_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00031.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"okular", rpm:"okular~17.04.2~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"okular-debuginfo", rpm:"okular-debuginfo~17.04.2~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"okular-debugsource", rpm:"okular-debugsource~17.04.2~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"okular-devel", rpm:"okular-devel~17.04.2~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"okular-lang", rpm:"okular-lang~17.04.2~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
