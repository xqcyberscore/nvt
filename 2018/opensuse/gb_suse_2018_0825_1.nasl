###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0825_1.nasl 9269 2018-03-30 05:36:10Z santu $
#
# SuSE Update for clamav openSUSE-SU-2018:0825-1 (clamav)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851727");
  script_version("$Revision: 9269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-30 07:36:10 +0200 (Fri, 30 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-28 08:51:56 +0200 (Wed, 28 Mar 2018)");
  script_cve_id("CVE-2012-6706", "CVE-2017-11423", "CVE-2017-6419", "CVE-2018-0202", 
                "CVE-2018-1000085");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for clamav openSUSE-SU-2018:0825-1 (clamav)");
  script_tag(name: "summary", value: "Check the version of clamav");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for clamav fixes the following issues:

  Security issues fixed:

  - CVE-2012-6706: VMSF_DELTA filter inside the unrar implementation allows
  an arbitrary memory write (bsc#1045315).
  - CVE-2017-6419: A heap-based buffer overflow that can lead to a denial of
  service in libmspack via a crafted CHM file (bsc#1052449).
  - CVE-2017-11423: A stack-based buffer over-read that can lead to a denial
  of service in mspack via a crafted CAB file (bsc#1049423).
  - CVE-2018-1000085: An out-of-bounds heap read vulnerability was found in
  XAR parser that can lead to a denial of service (bsc#1082858).
  - CVE-2018-0202: Fixed two vulnerabilities in the PDF parsing code
  (bsc#1083915).

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-314=1");
  script_tag(name: "affected", value: "clamav on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0825_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-03/msg00062.html");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.99.4~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.99.4~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.99.4~23.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
