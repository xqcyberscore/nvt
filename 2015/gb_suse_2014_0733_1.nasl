###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0733_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for IBM SUSE-SU-2014:0733-1 (IBM)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851093");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 19:47:47 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0428", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0448", "CVE-2014-0449", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-0878", "CVE-2014-1876", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2402", "CVE-2014-2409", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2420", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-2428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for IBM SUSE-SU-2014:0733-1 (IBM)");
  script_tag(name: "summary", value: "Check the version of IBM");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  IBM Java 7 was updated to version SR7, which received security and bug
  fixes.

  More information is available at:
  http://www.ibm.com/developerworks/java/jdk/aix/j764/Java7_64.fixes.html#SR7
  http://www.ibm.com/developerworks/java/jdk/aix/j764/Java7_64.fixes.html#SR7 

  Security Issues references:

  * CVE-2013-6629
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6629 
  * CVE-2013-6954
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6954 
  * CVE-2014-0429
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0429 
  * CVE-2014-0446
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0446 
  * CVE-2014-0448
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0448 
  * CVE-2014-0449
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0449 
  * CVE-2014-0451
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0451 
  * CVE-2014-0452
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0452 
  * CVE-2014-0457
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0457 
  * CVE-2014-0458
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0458 
  * CVE-2014-0459
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0459 
  * CVE-2014-0460
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0460 
  * CVE-2014-0461
  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "IBM on SUSE Linux Enterprise Server 11 SP2 LTSS");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0733_1");
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

if(release == "SLES11.0SP2")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-ibm", rpm:"java-1_7_0-ibm~1.7.0_sr7.0~0.5.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-ibm-devel", rpm:"java-1_7_0-ibm-devel~1.7.0_sr7.0~0.5.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-ibm-jdbc", rpm:"java-1_7_0-ibm-jdbc~1.7.0_sr7.0~0.5.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-ibm-alsa", rpm:"java-1_7_0-ibm-alsa~1.7.0_sr7.0~0.5.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-ibm-plugin", rpm:"java-1_7_0-ibm-plugin~1.7.0_sr7.0~0.5.1", rls:"SLES11.0SP2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
