###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0967_1.nasl 8046 2017-12-08 08:48:56Z santu $
#
# SuSE Update for the SUSE-SU-2014:0967-1 (apache2)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850761");
  script_version("$Revision: 8046 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 09:48:56 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for the SUSE-SU-2014:0967-1 (apache2)");
  script_tag(name: "summary", value: "Check the version of the apache2");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "
  This update for the Apache Web Server provides the following fixes:

  * Fixed a heap-based buffer overflow on apache module mod_status.
  (bnc#887765, CVE-2014-0226)
  * Properly remove whitespace characters from CDATA sections to avoid
  remote denial of service by crashing the Apache Server process.
  (bnc#869105, CVE-2013-6438)
  * Correction to parsing of cookie content  this can lead to a crash
  with a specially designed cookie sent to the server. (bnc#869106,
  CVE-2014-0098)
  * ECC support should not be missing. (bnc#859916)

  This update also introduces a new configuration parameter
  CGIDScriptTimeout, which defaults to the value of parameter Timeout.
  CGIDScriptTimeout is set to 60s if mod_cgid is loaded/active, via
  /etc/apache2/conf.d/cgid-timeout.conf. The new directive and its effect
  prevent request workers to be eaten until starvation if cgi programs do
  not send output back to the server within the timeout set by
  CGIDScriptTimeout. (bnc#887768, CVE-2014-0231)

  Security Issues references:

  * CVE-2014-0226
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0226 
  * CVE-2013-6438
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-6438 
  * CVE-2014-0098
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0098 
  * CVE-2014-0231
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0231");
  script_tag(name: "affected", value: "apache2 on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0967_1");
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

  if ((res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.12~1.46.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.12~1.46.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.12~1.46.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.12~1.46.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.12~1.46.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.12~1.46.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
