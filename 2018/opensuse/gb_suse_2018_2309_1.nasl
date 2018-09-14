###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2309_1.nasl 11370 2018-09-13 11:32:51Z asteins $
#
# SuSE Update for mailman openSUSE-SU-2018:2309-1 (mailman)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851851");
  script_version("$Revision: 11370 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 13:32:51 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-14 05:56:27 +0200 (Tue, 14 Aug 2018)");
  script_cve_id("CVE-2018-13796");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for mailman openSUSE-SU-2018:2309-1 (mailman)");
  script_tag(name:"summary", value:"Check the version of mailman");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"
  This update for mailman fixes the following issues:

  Security issue fixed:

  - CVE-2018-13796: Fix a content spoofing vulnerability with invalid list
  name messages inside the web UI (boo#1101288).

  Bug fixes:

  - update to 2.1.29:
  * Fixed the listinfo and admin overview pages that were broken

  - update to 2.1.28:
  * It is now possible to edit HTML and text templates via the web admin
  UI in a supported language other than the list's preferred_language.
  * The Japanese translation has been updated
  * The German translation has been updated
  * The Esperanto translation has been updated
  * The BLOCK_SPAMHAUS_LISTED_DBL_SUBSCRIBE feature added in 2.1.27 was
  not working.  This is fixed.
  * Escaping of HTML entities for the web UI is now done more selectively.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-861=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-861=1");
  script_tag(name:"affected", value:"mailman on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:2309_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-08/msg00046.html");
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

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.29~2.11.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.29~2.11.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mailman-debugsource", rpm:"mailman-debugsource~2.1.29~2.11.2", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
