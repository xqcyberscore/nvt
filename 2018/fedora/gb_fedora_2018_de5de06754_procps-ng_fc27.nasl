###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_de5de06754_procps-ng_fc27.nasl 10349 2018-06-27 15:50:28Z cfischer $
#
# Fedora Update for procps-ng FEDORA-2018-de5de06754
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874602");
  script_version("$Revision: 10349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-27 17:50:28 +0200 (Wed, 27 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-25 05:57:13 +0200 (Fri, 25 May 2018)");
  script_cve_id("CVE-2018-1124", "CVE-2018-1126");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for procps-ng FEDORA-2018-de5de06754");
  script_tag(name:"summary", value:"Check the version of procps-ng");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"The procps package contains a set of system 
utilities that provide system information. Procps includes ps, free, skill, pkill, 
pgrep, snice, tload, top, uptime, vmstat, w, watch and pwdx. The ps command 
displays a snapshot of running processes. The top command provides a repetitive 
update of the statuses of running processes. The free command displays the amounts 
of free and used memory on your system. The skill command sends a terminate command 
(or another specified signal) to a specified set of processes. The snice command 
is used to change the scheduling priority of specified processes. The tload 
command prints a graph of the current system load average to a specified tty. 
The uptime command displays the current time, how long the system has been running, 
how many users are logged on, and system load averages for the past one, five,
and fifteen minutes. The w command displays a list of the users who are currently 
logged on and what they are running. The watch program watches a running program. 
The vmstat command displays virtual memory statistics about processes, memory, 
paging, block I/O, traps, and CPU activity. The pwdx command reports the current
working directory of a process or processes.
");
  script_tag(name:"affected", value:"procps-ng on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-de5de06754");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EOSXM6XK4Q5ZVHOEKCXBSWFMCCYLPD2E");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"procps-ng", rpm:"procps-ng~3.3.10~16.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
