###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ndjbdns FEDORA-2012-20959
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_affected = "ndjbdns on Fedora 16";
tag_insight = "New djbdns: is a usable fork of djbdns. `djbdns' is a Domain Name System
  originally written by the eminent author of Qmail, Dr D. J. Bernstein.
  This *new* version of djbdns is a complete makeover to the original
  source(djbdns-1.05) and is meant to make life a lot more pleasant. The
  notable changes so far are in the set-up &amp; configuration steps and
  integration with the systemd(1) framework. This new release is free from
  the clutches of `daemon-tools'. The original source is in public-domain
  since late Dec 2007(see: http://cr.yp.to/distributors.html);";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/095331.html");
  script_oid("1.3.6.1.4.1.25623.1.0.864968");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-04 12:34:02 +0530 (Fri, 04 Jan 2013)");
  script_cve_id("CVE-2008-4392");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name: "FEDORA", value: "2012-20959");
  script_name("Fedora Update for ndjbdns FEDORA-2012-20959");

  script_tag(name: "summary" , value: "Check for the Version of ndjbdns");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"ndjbdns", rpm:"ndjbdns~1.05.5~1.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
