###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0298_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for clamav SUSE-SU-2015:0298-1 (clamav)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850824");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-9328", "CVE-2015-1461", "CVE-2015-1462", "CVE-2015-1463");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for clamav SUSE-SU-2015:0298-1 (clamav)");
  script_tag(name: "summary", value: "Check the version of clamav");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  clamav was updated to version 0.98.6 to fix four security issues.

  These security issues have been fixed:

  * CVE-2015-1462: ClamAV allowed remote attackers to have unspecified
  impact via a crafted upx packer file, related to a heap out of
  bounds condition (bnc#916214).
  * CVE-2015-1463: ClamAV allowed remote attackers to cause a denial of
  service (crash) via a crafted petite packer file, related to an
  incorrect compiler optimization (bnc#916215).
  * CVE-2014-9328: ClamAV allowed remote attackers to have unspecified
  impact via a crafted upack packer file, related to a heap out of
  bounds condition (bnc#915512).
  * CVE-2015-1461: ClamAV allowed remote attackers to have unspecified
  impact via a crafted (1) Yoda's crypter or (2) mew packer file,
  related to a heap out of bounds condition (bnc#916217).

  Security Issues:

  * CVE-2015-1462
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1462 
  * CVE-2014-9328
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-9328 
  * CVE-2015-1463
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1463 
  * CVE-2015-1461
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1461");
  script_tag(name: "affected", value: "clamav on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2015:0298_1");
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

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.6~0.6.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
