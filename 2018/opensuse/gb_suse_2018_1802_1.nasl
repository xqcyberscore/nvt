###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1802_1.nasl 10359 2018-06-28 11:32:28Z santu $
#
# SuSE Update for redis openSUSE-SU-2018:1802-1 (redis)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851796");
  script_version("$Revision: 10359 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-28 13:32:28 +0200 (Thu, 28 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-23 05:57:35 +0200 (Sat, 23 Jun 2018)");
  script_cve_id("CVE-2018-11218", "CVE-2018-11219");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for redis openSUSE-SU-2018:1802-1 (redis)");
  script_tag(name:"summary", value:"Check the version of redis");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"
  This update for redis to 4.0.10 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-11218: Prevent heap corruption vulnerability in cmsgpack
  (bsc#1097430).
  - CVE-2018-11219: Prevent integer overflow in Lua scripting (bsc#1097768).

  For Leap 42.3 and openSUSE SLE 12 backports this is a jump from 4.0.6. For
  additional details please see

  - 'https://raw.githubusercontent.com/antirez/redis/4.0.9/00-RELEASENOTES'
  - 'https://raw.githubusercontent.com/antirez/redis/4.0.8/00-RELEASENOTES'
  - 'https://raw.githubusercontent.com/antirez/redis/4.0.7/00-RELEASENOTES'


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-667=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-667=1");
  script_tag(name:"affected", value:"redis on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:1802_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00043.html");
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

  if ((res = isrpmvuln(pkg:"redis", rpm:"redis~4.0.10~17.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"redis-debuginfo", rpm:"redis-debuginfo~4.0.10~17.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"redis-debugsource", rpm:"redis-debugsource~4.0.10~17.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
