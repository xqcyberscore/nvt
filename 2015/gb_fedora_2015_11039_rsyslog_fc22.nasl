###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for rsyslog FEDORA-2015-11039
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
  script_oid("1.3.6.1.4.1.25623.1.0.869758");
  script_version("$Revision: 6851 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-04 09:31:24 +0200 (Fri, 04 Aug 2017) $");
  script_tag(name:"creation_date", value:"2015-07-16 06:15:17 +0200 (Thu, 16 Jul 2015)");
  script_cve_id("CVE-2015-3243");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for rsyslog FEDORA-2015-11039");
  script_tag(name: "summary", value: "Check the version of rsyslog");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Rsyslog is an enhanced, multi-threaded
syslog daemon. It supports MySQL, syslog/TCP, RFC 3195, permitted sender lists,
filtering on any message part, and fine grain output format control. It is
compatible with stock sysklogd and can be used as a drop-in replacement.
Rsyslog is simple to set up, with advanced features suitable for
enterprise-class, encryption-protected syslog relay chains.
");
  script_tag(name: "affected", value: "rsyslog on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-11039");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161996.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~8.8.0~3.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
