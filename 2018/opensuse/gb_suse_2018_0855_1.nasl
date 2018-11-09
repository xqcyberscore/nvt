###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0855_1.nasl 12257 2018-11-08 10:34:56Z santu $
#
# SuSE Update for memcached openSUSE-SU-2018:0855-1 (memcached)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851729");
  script_version("$Revision: 12257 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 11:34:56 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-31 08:55:01 +0200 (Sat, 31 Mar 2018)");
  script_cve_id("CVE-2017-9951");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for memcached openSUSE-SU-2018:0855-1 (memcached)");
  script_tag(name: "summary", value: "Check the version of memcached");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name:"insight", value:"This update for memcached fixes the following issues:

  - CVE-2017-9951: Fixed heap-based buffer over-read in try_read_command
  function which allowed remote attackers to cause a denial of service
  attack (bsc#1056865).

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-327=1");
  script_tag(name: "affected", value: "memcached on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0855_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00074.html");
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

  if ((res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.4.39~11.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"memcached-debuginfo", rpm:"memcached-debuginfo~1.4.39~11.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"memcached-debugsource", rpm:"memcached-debugsource~1.4.39~11.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"memcached-devel", rpm:"memcached-devel~1.4.39~11.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
