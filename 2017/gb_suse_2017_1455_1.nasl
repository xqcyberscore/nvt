###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1455_1.nasl 9381 2018-04-06 11:21:01Z cfischer $
#
# SuSE Update for sudo openSUSE-SU-2017:1455-1 (sudo)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851561");
  script_version("$Revision: 9381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 13:21:01 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2017-06-01 06:56:32 +0200 (Thu, 01 Jun 2017)");
  script_cve_id("CVE-2017-1000367");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for sudo openSUSE-SU-2017:1455-1 (sudo)");
  script_tag(name: "summary", value: "Check the version of sudo");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of 
  detect NVT and check if the version is vulnerable or not."); 
  script_tag(name: "insight", value:"This update for sudo fixes the following 
  issues: CVE-2017-1000367: - Due to incorrect assumptions in /proc/[pid]/stat 
  parsing, a local attacker can pretend that his tty is any file on the 
  filesystem, thus gaining arbitrary file write access on SELinux-enabled systems. 
  [bsc#1039361] - Fix FQDN for hostname. [bsc#1024145] - Filter netgroups, they 
  aren't handled by SSSD. [bsc#1015351] - Fix problems related to 'krb5_ccname' 
  option [bsc#981124] This update was imported from the SUSE:SLE-12-SP2:Update 
  update project."); 
  script_tag(name: "affected", value: "sudo on openSUSE Leap 42.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2017:1455_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.8.10p3~9.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debuginfo", rpm:"sudo-debuginfo~1.8.10p3~9.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-debugsource", rpm:"sudo-debugsource~1.8.10p3~9.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.8.10p3~9.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sudo-test", rpm:"sudo-test~1.8.10p3~9.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}