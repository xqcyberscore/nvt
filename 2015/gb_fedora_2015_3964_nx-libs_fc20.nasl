###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for nx-libs FEDORA-2015-3964
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
  script_oid("1.3.6.1.4.1.25623.1.0.869126");
  script_version("$Revision: 6630 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:34:32 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-03-27 06:46:43 +0100 (Fri, 27 Mar 2015)");
  script_cve_id("CVE-2011-2895", "CVE-2011-4028", "CVE-2013-4396", "CVE-2013-6462",
                "CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211", "CVE-2014-8092",
                "CVE-2014-8097", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8099",
                "CVE-2014-8100", "CVE-2014-8102", "CVE-2014-8101", "CVE-2014-8093",
                "CVE-2014-8098", "CVE-2015-0255");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for nx-libs FEDORA-2015-3964");
  script_tag(name: "summary", value: "Check the version of nx-libs");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "NX is a software suite which implements
very efficient compression of the X11 protocol. This increases performance when
using X applications over a network, especially a slow one.

This package provides the core nx-X11 libraries customized for nxagent/x2goagent.
");
  script_tag(name: "affected", value: "nx-libs on Fedora 20");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-3964");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-March/152878.html");
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

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"nx-libs", rpm:"nx-libs~3.5.0.29~1.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
