###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_3144_1.nasl 8049 2017-12-08 09:11:55Z santu $
#
# SuSE Update for kernel-firmware openSUSE-SU-2017:3144-1 (kernel-firmware)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851654");
  script_version("$Revision: 8049 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:11:55 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-04 18:47:56 +0530 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2017-13080", "CVE-2017-13081");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for kernel-firmware openSUSE-SU-2017:3144-1 (kernel-firmware)");
  script_tag(name: "summary", value: "Check the version of kernel-firmware");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for kernel-firmware fixes the following issues:

  - Update Intel WiFi firmwares for the 3160, 7260 and 7265 adapters.

  Security issues fixed are part of the 'KRACK' attacks affecting the
  firmware:

  - CVE-2017-13080: The reinstallation of the Group Temporal key could be
  used for replay attacks (bsc#1066295):
  - CVE-2017-13081: The reinstallation of the Integrity Group Temporal key
  could be used for replay attacks (bsc#1066295):

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");
  script_tag(name: "affected", value: "kernel-firmware on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2017:3144_1");
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

  if ((res = isrpmvuln(pkg:"kernel-firmware-20170530", rpm:"kernel-firmware-20170530~7.9.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-amd-20170530", rpm:"ucode-amd-20170530~7.9.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"kernel-firmware-20170530", rpm:"kernel-firmware-20170530~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ucode-amd-20170530", rpm:"ucode-amd-20170530~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
