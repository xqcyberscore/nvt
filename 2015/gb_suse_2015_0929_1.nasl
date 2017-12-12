###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0929_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for KVM SUSE-SU-2015:0929-1 (KVM)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850901");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 13:50:39 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-0222", "CVE-2014-0223", "CVE-2015-3456");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for KVM SUSE-SU-2015:0929-1 (KVM)");
  script_tag(name: "summary", value: "Check the version of KVM");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  KVM was updated to fix the following security issues:

  * CVE-2015-3456: Buffer overflow in the floppy drive emulation, which
  could be used to carry out denial of service attacks or potential
  code execution against the host. This vulnerability is also known as
  VENOM.
  * CVE-2014-0222: Integer overflow in the qcow_open function in
  block/qcow.c in QEMU allowed remote attackers to cause a denial of
  service (crash) via a large L2 table in a QCOW version 1 image.
  * CVE-2014-0223: Integer overflow in the qcow_open function in
  block/qcow.c in QEMU allowed local users to cause a denial of
  service (crash) and possibly execute arbitrary code via a large
  image size, which triggers a buffer overflow or out-of-bounds read.

  Security Issues:

  * CVE-2015-3456
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3456 
  * CVE-2014-0222
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0222 
  * CVE-2014-0223
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0223 


  Special Instructions and Notes:

  Please reboot the system after installing this update.");
  script_tag(name: "affected", value: "KVM on SUSE Linux Enterprise Server 11 SP1 LTSS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2015:0929_1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "SLES11.0SP1")
{

  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~0.12.5~1.26.1", rls:"SLES11.0SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}