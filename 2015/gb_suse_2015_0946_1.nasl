###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0946_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for MySQL SUSE-SU-2015:0946-1 (MySQL)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850827");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0405", "CVE-2015-0423", "CVE-2015-0433", "CVE-2015-0438", "CVE-2015-0439", "CVE-2015-0441", "CVE-2015-0498", "CVE-2015-0499", "CVE-2015-0500", "CVE-2015-0501", "CVE-2015-0503", "CVE-2015-0505", "CVE-2015-0506", "CVE-2015-0507", "CVE-2015-0508", "CVE-2015-0511", "CVE-2015-2305", "CVE-2015-2566", "CVE-2015-2567", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2576");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for MySQL SUSE-SU-2015:0946-1 (MySQL)");
  script_tag(name: "summary", value: "Check the version of MySQL");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  MySQL was updated to version 5.5.43 to fix several security and non
  security issues:

  * CVEs fixed: CVE-2014-3569, CVE-2014-3570, CVE-2014-3571,
  CVE-2014-3572, CVE-2014-8275, CVE-2015-0204, CVE-2015-0205,
  CVE-2015-0206, CVE-2015-0405, CVE-2015-0423, CVE-2015-0433,
  CVE-2015-0438, CVE-2015-0439, CVE-2015-0441, CVE-2015-0498,
  CVE-2015-0499, CVE-2015-0500, CVE-2015-0501, CVE-2015-0503,
  CVE-2015-0505, CVE-2015-0506, CVE-2015-0507, CVE-2015-0508,
  CVE-2015-0511, CVE-2015-2566, CVE-2015-2567, CVE-2015-2568,
  CVE-2015-2571, CVE-2015-2573, CVE-2015-2576.
  * Fix integer overflow in regcomp (Henry Spencer's regex library) for
  excessively long pattern strings. (bnc#922043, CVE-2015-2305)

  For a comprehensive list of changes, refer to
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html
http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-43.html  .

  Security Issues:

  * CVE-2014-3569
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3569 
  * CVE-2014-3570
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3570 
  * CVE-2014-3571
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3571 
  * CVE-2014-3572
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3572 
  * CVE-2014-8275
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8275 
  * CVE-2015-0204
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0204 
  * CVE-2015-0205
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0205 
  * CVE-2015-0206
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0206 
  * CVE-2015-0405
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0405 
  * CVE-2015- ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "MySQL on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2015:0946_1");
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

  if ((res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.20", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.20", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.20", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.43~0.7.3", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.20", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
