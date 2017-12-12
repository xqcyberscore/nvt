###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1072_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for MySQL SUSE-SU-2014:1072-1 (MySQL)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850819");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-2484", "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4214", "CVE-2014-4233", "CVE-2014-4238", "CVE-2014-4240", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MySQL SUSE-SU-2014:1072-1 (MySQL)");
  script_tag(name: "summary", value: "Check the version of MySQL");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This MySQL update provides the following:

  * upgrade to version 5.5.39, [bnc#887580]
  * CVE's fixed: CVE-2014-2484, CVE-2014-4258, CVE-2014-4260,
  CVE-2014-2494, CVE-2014-4238, CVE-2014-4207, CVE-2014-4233,
  CVE-2014-4240, CVE-2014-4214, CVE-2014-4243

  See also:
http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html 

  Security Issues:

  * CVE-2014-2484
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2484 
  * CVE-2014-4258
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4258 
  * CVE-2014-4260
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4260 
  * CVE-2014-2494
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2494 
  * CVE-2014-4238
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4238 
  * CVE-2014-4207
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4207 
  * CVE-2014-4233
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4233 
  * CVE-2014-4240
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4240 
  * CVE-2014-4214
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4214 
  * CVE-2014-4243
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4243");
  script_tag(name: "affected", value: "MySQL on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:1072_1");
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

  if ((res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.13", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.13", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.13", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.39~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.13", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
