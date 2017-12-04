###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_5adf087854_perl-Net-Ping-External_fc27.nasl 7911 2017-11-27 04:54:41Z santu $
#
# Fedora Update for perl-Net-Ping-External FEDORA-2017-5adf087854
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
  script_oid("1.3.6.1.4.1.25623.1.0.873725");
  script_version("$Revision: 7911 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-27 05:54:41 +0100 (Mon, 27 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:11:05 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2008-7319");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for perl-Net-Ping-External FEDORA-2017-5adf087854");
  script_tag(name: "summary", value: "Check the version of perl-Net-Ping-External");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Net::Ping::External is a module which 
interfaces with the 'ping' command on many systems. It presently provides a 
single function, ping(), that takes in a hostname and (optionally) a timeout 
and returns true if the host is alive, and false otherwise. Unless you have 
the ability (and willingness) to run your scripts as the superuser on your 
system, this module will probably provide more accurate results than Net::Ping 
will.");
  script_tag(name: "affected", value: "perl-Net-Ping-External on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-5adf087854");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LD25S5A76YTCZZA5ARSIF3ATPTDDLYY2");
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

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"perl-Net-Ping-External", rpm:"perl-Net-Ping-External~0.15~11.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
