###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3438_1.nasl 12257 2018-11-08 10:34:56Z santu $
#
# SuSE Update for ntp openSUSE-SU-2018:3438-1 (ntp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852021");
  script_version("$Revision: 12257 $");
  script_cve_id("CVE-2018-12327", "CVE-2018-7170");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 11:34:56 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:35:00 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for ntp openSUSE-SU-2018:3438-1 (ntp)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");

  script_xref(name:"openSUSE-SU", value:"2018:3438_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00064.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the openSUSE-SU-2018:3438_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for NTP to version 4.2.8p12 fixes the following
  vulnerabilities (bsc#1111853):

  - CVE-2018-12327: Fixed stack buffer overflow in the openhost()
  command-line call of NTPQ/NTPDC. (bsc#1098531)
  - CVE-2018-7170: Add further tweaks to improve the fix for the ephemeral
  association time spoofing additional protection (bsc#1083424)

  more information.

  This update was imported from the SUSE:SLE-12-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1280=1");

  script_tag(name:"affected", value:"ntp on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p12~31.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p12~31.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p12~31.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p12~31.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
