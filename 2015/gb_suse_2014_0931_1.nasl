###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0931_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for libtasn1 SUSE-SU-2014:0931-1 (libtasn1)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850814");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libtasn1 SUSE-SU-2014:0931-1 (libtasn1)");
  script_tag(name: "summary", value: "Check the version of libtasn1");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  libtasn1 has been updated to fix three security issues:

  * asn1_get_bit_der() could have returned negative bit length
  (CVE-2014-3468)
  * Multiple boundary check issues could have allowed DoS (CVE-2014-3467)
  * Possible DoS by NULL pointer dereference in asn1_read_value_type
  (CVE-2014-3469)

  Security Issues:

  * CVE-2014-3468
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3468 
  * CVE-2014-3467
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3467 
  * CVE-2014-3469
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3469");
  script_tag(name: "affected", value: "libtasn1 on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0931_1");
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

  if ((res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~1.5~1.28.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-3", rpm:"libtasn1-3~1.5~1.28.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-3-32bit", rpm:"libtasn1-3-32bit~1.5~1.28.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-3-x86", rpm:"libtasn1-3-x86~1.5~1.28.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
