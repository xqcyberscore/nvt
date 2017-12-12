###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1619_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for shim SUSE-SU-2014:1619-1 (shim)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850767");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-3675", "CVE-2014-3676", "CVE-2014-3677");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for shim SUSE-SU-2014:1619-1 (shim)");
  script_tag(name: "summary", value: "Check the version of shim");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  shim has been updated to fix three security issues:

  * OOB read access when parsing DHCPv6 packets (remote DoS)
  (CVE-2014-3675).
  * Heap overflow when parsing IPv6 addresses provided by tftp:// DHCPv6
  boot option (RCE) (CVE-2014-3676).
  * Memory corruption when processing user provided MOK lists
  (CVE-2014-3677).

  Security Issues:

  * CVE-2014-3675
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3675 
  * CVE-2014-3676
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3676 
  * CVE-2014-3677
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3677");
  script_tag(name: "affected", value: "shim on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:1619_1");
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

  if ((res = isrpmvuln(pkg:"gnu-efi", rpm:"gnu-efi~3.0u~0.7.2", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"shim", rpm:"shim~0.7.318.81ee561d~0.9.2", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
