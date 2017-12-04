###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_9d345f250a_nagios_fc25.nasl 7920 2017-11-28 07:49:35Z asteins $
#
# Fedora Update for nagios FEDORA-2017-9d345f250a
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.873744");
  script_version("$Revision: 7920 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-28 08:49:35 +0100 (Tue, 28 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:13:01 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-14312");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nagios FEDORA-2017-9d345f250a");
  script_tag(name: "summary", value: "Check the version of nagios");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Nagios is a program that will monitor hosts 
and services on your network.  It has the ability to send email or page alerts 
when a problem arises and when a problem is resolved.  Nagios is written in C and 
is designed to run under Linux (and some other *NIX variants) as a background 
process, intermittently running checks on various services that you specify.

The actual service checks are performed by separate 'plugin' programs
which return the status of the checks to Nagios. The plugins are
available at 'https://github.com/nagios-plugins/nagios-plugins'

This package provides the core program, web interface, and documentation
files for Nagios. Development files are built as a separate package.
");
  script_tag(name: "affected", value: "nagios on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-9d345f250a");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/44ASMMUK4H2NFLSOKZ36AQH6JI3EZW7V");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"nagios", rpm:"nagios~4.3.4~3.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
