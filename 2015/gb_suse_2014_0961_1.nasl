###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0961_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for openjdk SUSE-SU-2014:0961-1 (openjdk)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850985");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:11:31 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4208", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4220", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4227", "CVE-2014-4244", "CVE-2014-4247", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4264", "CVE-2014-4265", "CVE-2014-4266", "CVE-2014-4268");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for openjdk SUSE-SU-2014:0961-1 (openjdk)");
  script_tag(name: "summary", value: "Check the version of openjdk");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This Critical Patch Update contains 20 new security fixes for Oracle Java
  SE. All of these vulnerabilities could have been remotely exploitable
  without authentication, i.e., could be exploited over a network without
  the need for a username and password.

  Security Issues:

  * CVE-2014-4227
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4227 
  * CVE-2014-4219
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4219 
  * CVE-2014-2490
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2490 
  * CVE-2014-4216
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4216 
  * CVE-2014-4247
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4247 
  * CVE-2014-2483
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2483 
  * CVE-2014-4223
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4223 
  * CVE-2014-4262
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4262 
  * CVE-2014-4209
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4209 
  * CVE-2014-4265
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4265 
  * CVE-2014-4220
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4220 
  * CVE-2014-4218
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4218 
  * CVE-2014-4252
   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-4252 
  * CVE-2014-4266
   http://cve.mitre.org/cgi-bin/cvename.cgi ... 

  Description truncated, for more information please check the Reference URL");
  script_tag(name: "affected", value: "openjdk on SUSE Linux Enterprise Desktop 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0961_1");
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

if(release == "SLED11.0SP3")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.65~0.7.4", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.65~0.7.4", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.65~0.7.4", rls:"SLED11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
