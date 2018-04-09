###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for logrotate FEDORA-2011-3739
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The logrotate utility is designed to simplify the administration of
  log files on a system which generates a lot of log files.  Logrotate
  allows for the automatic rotation compression, removal and mailing of
  log files.  Logrotate can be set to handle a log file daily, weekly,
  monthly or when the log file gets to a certain size.  Normally,
  logrotate runs as a daily cron job.

  Install the logrotate package if you need a utility to deal with the
  log files on your system.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "logrotate on Fedora 14";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-April/057845.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862978");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-19 07:58:39 +0200 (Tue, 19 Apr 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2011-3739");
  script_cve_id("CVE-2011-1154", "CVE-2011-1155", "CVE-2011-1098");
  script_name("Fedora Update for logrotate FEDORA-2011-3739");

  script_tag(name:"summary", value:"Check for the Version of logrotate");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"logrotate", rpm:"logrotate~3.7.9~2.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
