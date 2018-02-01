###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0258_1.nasl 8606 2018-01-31 13:07:06Z santu $
#
# SuSE Update for clamav openSUSE-SU-2018:0258-1 (clamav)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851691");
  script_version("$Revision: 8606 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 14:07:06 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-29 07:46:42 +0100 (Mon, 29 Jan 2018)");
  script_cve_id("CVE-2017-11423", "CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", 
                "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", 
                "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for clamav openSUSE-SU-2018:0258-1 (clamav)");
  script_tag(name: "summary", value: "Check the version of clamav");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for clamav fixes the following issues:

  - Update to security release 0.99.3 (bsc#1077732)
  * CVE-2017-12376 (ClamAV Buffer Overflow in handle_pdfname Vulnerability)
  * CVE-2017-12377 (ClamAV Mew Packet Heap Overflow Vulnerability)
  * CVE-2017-12379 (ClamAV Buffer Overflow in messageAddArgument
  Vulnerability)
  - these vulnerabilities could have allowed an unauthenticated, remote
  attacker to cause a denial of service (DoS) condition
  or potentially execute arbitrary code on an affected device.
  * CVE-2017-12374 (ClamAV use-after-free Vulnerabilities)
  * CVE-2017-12375 (ClamAV Buffer Overflow Vulnerability)
  * CVE-2017-12378 (ClamAV Buffer Over Read Vulnerability)
  * CVE-2017-12380 (ClamAV Null Dereference Vulnerability)
  - these vulnerabilities could have allowed an unauthenticated, remote
  attacker to cause a denial of service (DoS) condition on an affected
  device.
  * CVE-2017-6420 (bsc#1052448)
  - this vulnerability could have allowed remote attackers to cause a
  denial of service (use-after-free) via a crafted PE file with WWPack
  compression.
  * CVE-2017-6419 (bsc#1052449)
  - ClamAV could have allowed remote attackers to cause a denial of
  service (heap-based buffer overflow and application crash) or
  possibly have unspecified other impact via a crafted CHM file.
  * CVE-2017-11423 (bsc#1049423)
  - ClamAV could have allowed remote attackers to cause a denial of
  service (stack-based buffer over-read and application crash) via a
  crafted CAB file.
  * CVE-2017-6418 (bsc#1052466)
  - ClamAV could have allowed remote attackers to cause a denial
  of service (out-of-bounds read) via a crafted e-mail message.
  - update upstream keys in the keyring

  - provide and obsolete clamav-nodb to trigger it's removal in Leap
  bsc#1040662

  This update was imported from the SUSE:SLE-12:Update update project.");
  script_tag(name: "affected", value: "clamav on openSUSE Leap 42.3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "openSUSE-SU", value: "2018:0258_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2018-01/msg00078.html");
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

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.99.3~20.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.99.3~20.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.99.3~20.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
