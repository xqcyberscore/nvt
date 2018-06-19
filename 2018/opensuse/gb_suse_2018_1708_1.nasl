###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1708_1.nasl 10247 2018-06-19 07:14:03Z santu $
#
# SuSE Update for enigmail openSUSE-SU-2018:1708-1 (enigmail)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851788");
  script_version("$Revision: 10247 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-19 09:14:03 +0200 (Tue, 19 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-16 05:50:35 +0200 (Sat, 16 Jun 2018)");
  script_cve_id("CVE-2018-12019", "CVE-2018-12020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for enigmail openSUSE-SU-2018:1708-1 (enigmail)");
  script_tag(name:"summary", value:"Check the version of enigmail");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"
  This update for enigmail fixes vulnerabilities that allowed spoofing of
  e-mail signatures:

  - CVE-2018-12019: signature spoofing via specially crafted OpenPGP user
  IDs (boo#1097525)
  - CVE-2018-12020: signature spoofing via diagnostic output of the original
  file name in GnuPG verbose mode (boo#1096745) This mitigation prevents
  CVE-2018-12020 from being exploited even if GnuPG is not patched.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended 
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-630=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-630=1");
  script_tag(name:"affected", value:"enigmail on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"openSUSE-SU", value:"2018:1708_1");
  script_xref(name:"URL" , value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00028.html");
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

  if ((res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~2.0.7~21.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
