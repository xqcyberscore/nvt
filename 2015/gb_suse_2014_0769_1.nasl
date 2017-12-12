###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0769_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for MySQL SUSE-SU-2014:0769-1 (MySQL)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850784");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-4316", "CVE-2013-5860", "CVE-2013-5881", "CVE-2013-5882",
                "CVE-2013-5891", "CVE-2013-5894", "CVE-2013-5908", "CVE-2014-0001",
                "CVE-2014-0384", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401",
                "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0427",
                "CVE-2014-0430", "CVE-2014-0431", "CVE-2014-0433", "CVE-2014-0437",
                "CVE-2014-2419", "CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2432",
                "CVE-2014-2434", "CVE-2014-2435", "CVE-2014-2436", "CVE-2014-2438",
                "CVE-2014-2440", "CVE-2014-2442", "CVE-2014-2444", "CVE-2014-2450",
                "CVE-2014-2451");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MySQL SUSE-SU-2014:0769-1 (MySQL)");
  script_tag(name: "summary", value: "Check the version of MySQL");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  MySQL was updated to version 5.5.37 to address various security issues.

  More information is available at
http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html#A
  ppendixMSQL
http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html#
  AppendixMSQL  and
http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#A
  ppendixMSQL
http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html#
  AppendixMSQL  .

  Security Issues references:

  * CVE-2014-2444
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2444 
  * CVE-2014-2436
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2436 
  * CVE-2014-2440
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2440 
  * CVE-2014-2434
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2434 
  * CVE-2014-2435
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2435 
  * CVE-2014-2442
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2442 
  * CVE-2014-2450
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2450 
  * CVE-2014-2419
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2419 
  * CVE-2014-0384
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0384 
  * CVE-2014-2430
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2430 
  * CVE-201 ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "MySQL on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0769_1");
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

  if ((res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.11", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.11", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.11", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.37~0.7.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.11", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
