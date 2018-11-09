###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0475_1.nasl 12259 2018-11-08 12:33:31Z santu $
#
# SuSE Update for sudo SUSE-SU-2014:0475-1 (sudo)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850754");
  script_version("$Revision: 12259 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:33:31 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2014-0106");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for sudo SUSE-SU-2014:0475-1 (sudo)");
  script_tag(name: "summary", value: "Check the version of sudo");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name:"insight", value:"This collective update for sudo provides fixes for the
  following issues:

  * Security policy bypass when env_reset is disabled.
  (CVE-2014-0106, bnc#866503)
  * Regression in the previous update that causes a
  segmentation fault when running 'sudo -s'. (bnc#868444)
  * Command 'who -m' prints no output when using
  log_input/log_output sudo options. (bnc#863025)

  Security Issues references:

  * CVE-2014-0106");
  script_tag(name: "affected", value: "sudo on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "SUSE-SU", value: "2014:0475_1");
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

  if ((res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.6p2~0.21.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
