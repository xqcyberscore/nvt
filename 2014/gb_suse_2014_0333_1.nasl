###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0333_1.nasl 9373 2018-04-06 08:57:18Z cfischer $
#
# SuSE Update for percona-toolkit,xtrabackup openSUSE-SU-2014:0333-1 (percona-toolkit,xtrabackup)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.850572");
  script_version("$Revision: 9373 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:57:18 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-03-12 09:29:13 +0530 (Wed, 12 Mar 2014)");
  script_cve_id("CVE-2014-2029");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("SuSE Update for percona-toolkit,xtrabackup openSUSE-SU-2014:0333-1 (percona-toolkit,xtrabackup)");

  tag_insight = "
  percona-toolkit and xtrabackup were updated:
  - disable automatic version check for all tools
  [bnc#864194] Prevents transmission of version information
  to an external host in the default configuration.
  CVE-2014-2029 Can be used by owner of a Percona Server
  (or an attacker who can control this destination for the
  client) to collect arbitrary MySQL configuration
  parameters and execute commands (with -v). Now the
  version check needs to be requested via command line or
  global/tool specific/user configuration. (--version-check)
  - added /etc/percona-toolkit/percona-toolkit.conf
  configuration directory and template configuration file";

  tag_affected = "percona-toolkit,xtrabackup on openSUSE 13.1";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "openSUSE-SU", value: "2014:0333_1");
  script_tag(name:"summary", value:"Check for the Version of percona-toolkit,xtrabackup");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"xtrabackup", rpm:"xtrabackup~2.1.7~13.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xtrabackup-debuginfo", rpm:"xtrabackup-debuginfo~2.1.7~13.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xtrabackup-debugsource", rpm:"xtrabackup-debugsource~2.1.7~13.2", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"percona-toolkit", rpm:"percona-toolkit~2.2.7~2.10.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
