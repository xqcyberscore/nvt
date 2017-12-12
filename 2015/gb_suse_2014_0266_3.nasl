###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0266_3.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for IBM SUSE-SU-2014:0266-3 (IBM)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850759");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5887", "CVE-2013-5888",
                "CVE-2013-5889", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899",
                "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373",
                "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0387", "CVE-2014-0403",
                "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416",
                "CVE-2014-0417", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424",
                "CVE-2014-0428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for IBM SUSE-SU-2014:0266-3 (IBM)");
  script_tag(name: "summary", value: "Check the version of IBM");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  IBM Java 6 was updated to version SR15-FP1 which received
  security and bug  fixes.

  More information at:
http://www.ibm.com/developerworks/java/jdk/alerts/#Oracle_Ja
  nuary_14_2014_CPU
http://www.ibm.com/developerworks/java/jdk/alerts/#Oracle_J
  anuary_14_2014_CPU 

  Security Issue references:

  * CVE-2014-0428
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0428
   
  * CVE-2014-0422
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0422
   
  * CVE-2013-5907
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-5907
   
  * CVE-2014-0417
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0417
   
  * CVE-2014-0373
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0373
   
  * CVE-2014-0423
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0423
   
  * CVE-2014-0376
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0376
   
  * CVE-2014-0376
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0376
   
  * CVE-2014-0416
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0416
   
  * CVE-2014-0368
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0368
   
  * CVE-2014-0411
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0411
   
  * CVE-2014-0428
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0428
   
  * CVE-2014-0422
   <a  rel='nofollow' href='http://cve.mitre.org/cgi-bin/cvename.c ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "IBM on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0266_3");
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

  if ((res = isrpmvuln(pkg:"java-1_6_0-ibm", rpm:"java-1_6_0-ibm~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-ibm-fonts", rpm:"java-1_6_0-ibm-fonts~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-ibm-jdbc", rpm:"java-1_6_0-ibm-jdbc~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-ibm-plugin", rpm:"java-1_6_0-ibm-plugin~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_6_0-ibm-alsa", rpm:"java-1_6_0-ibm-alsa~1.6.0_sr15.1~0.6.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
