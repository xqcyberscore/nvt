###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_24bd6c9d4a_systemd_fc28.nasl 12314 2018-11-12 09:01:54Z santu $
#
# Fedora Update for systemd FEDORA-2018-24bd6c9d4a
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.875239");
  script_version("$Revision: 12314 $");
  script_cve_id("CVE-2018-15687", "CVE-2018-15686", "CVE-2018-15688");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 10:01:54 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-05 06:18:32 +0100 (Mon, 05 Nov 2018)");
  script_name("Fedora Update for systemd FEDORA-2018-24bd6c9d4a");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");

  script_xref(name:"FEDORA", value:"2018-24bd6c9d4a");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GDWAO2SXI45GQ5PBFG3KWYVCHBVYCND4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the FEDORA-2018-24bd6c9d4a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"systemd is a system and service manager that runs as PID 1 and starts
the rest of the system. It provides aggressive parallelization
capabilities, uses socket and D-Bus activation for starting services,
offers on-demand starting of daemons, keeps track of processes using
Linux control groups, maintains mount and automount points, and
implements an elaborate transactional dependency-based service control
logic. systemd supports SysV and LSB init scripts and works as a
replacement for sysvinit. Other parts of this package are a logging daemon,
utilities to control basic system configuration like the hostname,
date, locale, maintain a list of logged-in users and running
containers and virtual machines, system accounts, runtime directories
and settings, and daemons to manage simple network configuration,
network time synchronization, log forwarding, and name resolution.
");

  script_tag(name:"affected", value:"systemd on Fedora 28.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"systemd", rpm:"systemd~238~10.git438ac26.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
